package gmsm

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
)

const (
	sm2_uncompressed byte = 0x04
	sm2_compressed02 byte = 0x02
	sm2_compressed03 byte = sm2_compressed02 | 0x01
	sm2_hybrid06     byte = 0x06
	sm2_hybrid07     byte = sm2_hybrid06 | 0x01
)

// PrivateKey represents an ECDSA SM2 private key.
// It implemented both crypto.Decrypter and crypto.Signer interfaces.
type PrivateKey struct {
	ecdsa.PrivateKey
	// inverseOfKeyPlus1 is set under inverseOfKeyPlus1Once
	inverseOfKeyPlus1     *Nat
	inverseOfKeyPlus1Once sync.Once
}

type pointMarshalMode byte

const (
	//MarshalUncompressed uncompressed mashal mode
	MarshalUncompressed pointMarshalMode = iota
	//MarshalCompressed compressed mashal mode
	MarshalCompressed
	//MarshalHybrid hybrid mashal mode
	MarshalHybrid
)

type ciphertextSplicingOrder byte

const (
	C1C3C2 ciphertextSplicingOrder = iota
	C1C2C3
)

type ciphertextEncoding byte

const (
	ENCODING_PLAIN ciphertextEncoding = iota
	ENCODING_ASN1
)

// EncrypterOpts encryption options
type EncrypterOpts struct {
	ciphertextEncoding      ciphertextEncoding
	pointMarshalMode        pointMarshalMode
	ciphertextSplicingOrder ciphertextSplicingOrder
}

// DecrypterOpts decryption options
type DecrypterOpts struct {
	ciphertextEncoding      ciphertextEncoding
	cipherTextSplicingOrder ciphertextSplicingOrder
}

// NewPlainEncrypterOpts creates a SM2 non-ASN1 encrypter options.
func NewPlainEncrypterOpts(marhsalMode pointMarshalMode, splicingOrder ciphertextSplicingOrder) *EncrypterOpts {
	return &EncrypterOpts{ENCODING_PLAIN, marhsalMode, splicingOrder}
}

// NewPlainDecrypterOpts creates a SM2 non-ASN1 decrypter options.
func NewPlainDecrypterOpts(splicingOrder ciphertextSplicingOrder) *DecrypterOpts {
	return &DecrypterOpts{ENCODING_PLAIN, splicingOrder}
}

func toBytes(curve elliptic.Curve, value *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) >> 3
	result := make([]byte, byteLen)
	value.FillBytes(result)
	return result
}

var defaultEncrypterOpts = &EncrypterOpts{ENCODING_PLAIN, MarshalUncompressed, C1C3C2}

var ASN1EncrypterOpts = &EncrypterOpts{ENCODING_ASN1, MarshalUncompressed, C1C3C2}

var ASN1DecrypterOpts = &DecrypterOpts{ENCODING_ASN1, C1C3C2}

// directSigning is a standard Hash value that signals that no pre-hashing
// should be performed.
var directSigning crypto.Hash = 0

// Signer SM2 special signer
type Signer interface {
	SignWithSM2(rand io.Reader, uid, msg []byte) ([]byte, error)
}

// SM2SignerOption implements crypto.SignerOpts interface.
// It is specific for SM2, used in private key's Sign method.
type SM2SignerOption struct {
	uid         []byte
	forceGMSign bool
}

// NewSM2SignerOption creates a SM2 specific signer option.
// forceGMSign - if use GM specific sign logic, if yes, should pass raw message to sign.
// uid - if forceGMSign is true, then you can pass uid, if no uid is provided, system will use default one.
func NewSM2SignerOption(forceGMSign bool, uid []byte) *SM2SignerOption {
	opt := &SM2SignerOption{
		uid:         uid,
		forceGMSign: forceGMSign,
	}
	if forceGMSign && len(uid) == 0 {
		opt.uid = defaultUID
	}
	return opt
}

// DefaultSM2SignerOpts uses default UID and forceGMSign is true.
var DefaultSM2SignerOpts = NewSM2SignerOption(true, nil)

func (*SM2SignerOption) HashFunc() crypto.Hash {
	return directSigning
}

// FromECPrivateKey convert an ecdsa private key to SM2 private key.
func (priv *PrivateKey) FromECPrivateKey(key *ecdsa.PrivateKey) (*PrivateKey, error) {
	if key.Curve != P256() {
		return nil, errors.New("sm2: it's NOT a sm2 curve private key")
	}
	priv.PrivateKey = *key
	return priv, nil
}

func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey)
	if !ok {
		return false
	}
	return priv.PublicKey.Equal(&xx.PublicKey) && bigIntEqual(priv.D, xx.D)
}

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
	return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}

// Sign signs digest with priv, reading randomness from rand. Compliance with GB/T 32918.2-2016.
// The opts argument is currently used for SM2SignerOption checking only.
// If the opts argument is SM2SignerOption and its ForceGMSign is true,
// digest argument will be treated as raw data and UID will be taken from opts.
//
// This method implements crypto.Signer, which is an interface to support keys
// where the private part is kept in, for example, a hardware module.
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return SignASN1(rand, priv, digest, opts)
}

// SignWithSM2 signs uid, msg with priv, reading randomness from rand. Compliance with GB/T 32918.2-2016.
// Deprecated: please use Sign method directly.
func (priv *PrivateKey) SignWithSM2(rand io.Reader, uid, msg []byte) ([]byte, error) {
	return priv.Sign(rand, msg, NewSM2SignerOption(true, uid))
}

// Decrypt decrypts ciphertext msg to plaintext.
// The opts argument should be appropriate for the primitive used.
// Compliance with GB/T 32918.4-2016 chapter 7.
func (priv *PrivateKey) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	var sm2Opts *DecrypterOpts
	sm2Opts, _ = opts.(*DecrypterOpts)
	return decrypt(priv, msg, sm2Opts)
}

const maxRetryLimit = 100

var (
	errCiphertextTooShort = errors.New("sm2: ciphertext too short")
)

// EncryptASN1 sm2 encrypt and output ASN.1 result, compliance with GB/T 32918.4-2016.
//
// The random parameter is used as a source of entropy to ensure that
// encrypting the same message twice doesn't result in the same ciphertext.
// Most applications should use [crypto/rand.Reader] as random.
func EncryptASN1(random io.Reader, pub *ecdsa.PublicKey, msg []byte) ([]byte, error) {
	return Encrypt(random, pub, msg, ASN1EncrypterOpts)
}

// Encrypt sm2 encrypt implementation, compliance with GB/T 32918.4-2016.
//
// The random parameter is used as a source of entropy to ensure that
// encrypting the same message twice doesn't result in the same ciphertext.
// Most applications should use [crypto/rand.Reader] as random.
func Encrypt(random io.Reader, pub *ecdsa.PublicKey, msg []byte, opts *EncrypterOpts) ([]byte, error) {
	//A3, requirement is to check if h*P is infinite point, h is 1
	if pub.X.Sign() == 0 && pub.Y.Sign() == 0 {
		return nil, errors.New("sm2: public key point is the infinity")
	}
	if len(msg) == 0 {
		return nil, nil
	}
	if opts == nil {
		opts = defaultEncrypterOpts
	}
	switch pub.Curve.Params() {
	case P256().Params():
		return encryptSM2EC(p256(), pub, random, msg, opts)
	default:
		return encryptLegacy(random, pub, msg, opts)
	}
}

func encryptSM2EC(c *sm2Curve, pub *ecdsa.PublicKey, random io.Reader, msg []byte, opts *EncrypterOpts) ([]byte, error) {
	Q, err := c.pointFromAffine(pub.X, pub.Y)
	if err != nil {
		return nil, err
	}
	var retryCount int = 0
	for {
		k, C1, err := randomPoint(c, random, false)
		if err != nil {
			return nil, err
		}
		C2, err := Q.ScalarMult(Q, k.Bytes(c.N))
		if err != nil {
			return nil, err
		}
		C2Bytes := C2.Bytes()[1:]
		c2 := SM3_Kdf(C2Bytes, len(msg))
		if ConstantTimeAllZero(c2) == 1 {
			retryCount++
			if retryCount > maxRetryLimit {
				return nil, fmt.Errorf("sm2: A5, failed to calculate valid t, tried %v times", retryCount)
			}
			continue
		}
		//A6, C2 = M + t;
		XORBytes(c2, msg, c2)

		//A7, C3 = hash(x2||M||y2)
		md := NewSM3()
		md.Write(C2Bytes[:len(C2Bytes)/2])
		md.Write(msg)
		md.Write(C2Bytes[len(C2Bytes)/2:])
		c3 := md.Sum(nil)

		if opts.ciphertextEncoding == ENCODING_PLAIN {
			return encodingCiphertext(opts, C1, c2, c3)
		}
		return encodingCiphertextASN1(C1, c2, c3)
	}
}

func encodingCiphertext(opts *EncrypterOpts, C1 *SM2P256Point, c2, c3 []byte) ([]byte, error) {
	var c1 []byte
	switch opts.pointMarshalMode {
	case MarshalCompressed:
		c1 = C1.BytesCompressed()
	default:
		c1 = C1.Bytes()
	}

	if opts.ciphertextSplicingOrder == C1C3C2 {
		// c1 || c3 || c2
		return append(append(c1, c3...), c2...), nil
	}
	// c1 || c2 || c3
	return append(append(c1, c2...), c3...), nil
}

func encodingCiphertextASN1(C1 *SM2P256Point, c2, c3 []byte) ([]byte, error) {
	c1 := C1.Bytes()
	var b Builder
	b.AddASN1(SEQUENCE, func(b *Builder) {
		addASN1IntBytes(b, c1[1:len(c1)/2+1])
		addASN1IntBytes(b, c1[len(c1)/2+1:])
		b.AddASN1OctetString(c3)
		b.AddASN1OctetString(c2)
	})
	return b.Bytes()
}

// GenerateKey generates a new SM2 private key.
//
// Most applications should use [crypto/rand.Reader] as rand. Note that the
// returned key does not depend deterministically on the bytes read from rand,
// and may change between calls and/or between versions.
func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	MaybeReadByte(rand)

	c := p256()
	k, Q, err := randomPoint(c, rand, true)
	if err != nil {
		return nil, err
	}

	priv := new(PrivateKey)
	priv.PublicKey.Curve = c.curve
	priv.D = new(big.Int).SetBytes(k.Bytes(c.N))
	priv.PublicKey.X, priv.PublicKey.Y, err = c.pointToAffine(Q)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// NewPrivateKey checks that key is valid and returns a SM2 PrivateKey.
//
// key - the private key byte slice, the length must be 32 for SM2.
func NewPrivateKey(key []byte) (*PrivateKey, error) {
	c := p256()
	if len(key) != c.N.Size() {
		return nil, errors.New("sm2: invalid private key size")
	}
	k, err := NewNat().SetBytes(key, c.N)
	if err != nil || k.IsZero() == 1 || k.Equal(c.nMinus1) == 1 {
		return nil, errInvalidPrivateKey
	}
	p, err := c.newPoint().ScalarBaseMult(k.Bytes(c.N))
	if err != nil {
		return nil, err
	}
	priv := new(PrivateKey)
	priv.PublicKey.Curve = c.curve
	priv.D = new(big.Int).SetBytes(k.Bytes(c.N))
	priv.PublicKey.X, priv.PublicKey.Y, err = c.pointToAffine(p)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// NewPrivateKeyFromInt checks that key is valid and returns a SM2 PrivateKey.
func NewPrivateKeyFromInt(key *big.Int) (*PrivateKey, error) {
	if key == nil {
		return nil, errors.New("sm2: invalid private key size")
	}
	keyBytes := make([]byte, p256().N.Size())
	return NewPrivateKey(key.FillBytes(keyBytes))
}

// NewPublicKey checks that key is valid and returns a PublicKey.
func NewPublicKey(key []byte) (*ecdsa.PublicKey, error) {
	c := p256()
	// Reject the point at infinity and compressed encodings.
	if len(key) == 0 || key[0] != 4 {
		return nil, errors.New("sm2: invalid public key")
	}
	// SetBytes also checks that the point is on the curve.
	p, err := c.newPoint().SetBytes(key)
	if err != nil {
		return nil, err
	}
	k := new(ecdsa.PublicKey)
	k.Curve = c.curve
	k.X, k.Y, err = c.pointToAffine(p)
	if err != nil {
		return nil, err
	}
	return k, nil
}

// Decrypt sm2 decrypt implementation by default DecrypterOpts{C1C3C2}.
// Compliance with GB/T 32918.4-2016.
func Decrypt(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	return decrypt(priv, ciphertext, nil)
}

// ErrDecryption represents a failure to decrypt a message.
// It is deliberately vague to avoid adaptive attacks.
var ErrDecryption = errors.New("sm2: decryption error")

func decrypt(priv *PrivateKey, ciphertext []byte, opts *DecrypterOpts) ([]byte, error) {
	ciphertextLen := len(ciphertext)
	if ciphertextLen <= 1+(priv.Params().BitSize/8)+SM3_Size {
		return nil, errCiphertextTooShort
	}
	switch priv.Curve.Params() {
	case P256().Params():
		return decryptSM2EC(p256(), priv, ciphertext, opts)
	default:
		return decryptLegacy(priv, ciphertext, opts)
	}
}

func decryptSM2EC(c *sm2Curve, priv *PrivateKey, ciphertext []byte, opts *DecrypterOpts) ([]byte, error) {
	C1, c2, c3, err := parseCiphertext(c, ciphertext, opts)
	if err != nil {
		return nil, ErrDecryption
	}
	d, err := NewNat().SetBytes(priv.D.Bytes(), c.N)
	if err != nil {
		return nil, ErrDecryption
	}

	C2, err := C1.ScalarMult(C1, d.Bytes(c.N))
	if err != nil {
		return nil, ErrDecryption
	}
	C2Bytes := C2.Bytes()[1:]
	msgLen := len(c2)
	msg := SM3_Kdf(C2Bytes, msgLen)
	if ConstantTimeAllZero(c2) == 1 {
		return nil, ErrDecryption
	}

	//B5, calculate msg = c2 ^ t
	XORBytes(msg, c2, msg)

	md := NewSM3()
	md.Write(C2Bytes[:len(C2Bytes)/2])
	md.Write(msg)
	md.Write(C2Bytes[len(C2Bytes)/2:])
	u := md.Sum(nil)

	if subtle.ConstantTimeCompare(u, c3) == 1 {
		return msg, nil
	}
	return nil, ErrDecryption
}

func parseCiphertext(c *sm2Curve, ciphertext []byte, opts *DecrypterOpts) (*SM2P256Point, []byte, []byte, error) {
	bitSize := c.curve.Params().BitSize
	// Encode the coordinates and let SetBytes reject invalid points.
	byteLen := (bitSize + 7) / 8
	splicingOrder := C1C3C2
	if opts != nil {
		splicingOrder = opts.cipherTextSplicingOrder
	}

	b := ciphertext[0]
	switch b {
	case sm2_uncompressed:
		if len(ciphertext) <= 1+2*byteLen+SM3_Size {
			return nil, nil, nil, errCiphertextTooShort
		}
		C1, err := c.newPoint().SetBytes(ciphertext[:1+2*byteLen])
		if err != nil {
			return nil, nil, nil, err
		}
		c2, c3 := parseCiphertextC2C3(ciphertext[1+2*byteLen:], splicingOrder)
		return C1, c2, c3, nil
	case sm2_compressed02, sm2_compressed03:
		C1, err := c.newPoint().SetBytes(ciphertext[:1+byteLen])
		if err != nil {
			return nil, nil, nil, err
		}
		c2, c3 := parseCiphertextC2C3(ciphertext[1+byteLen:], splicingOrder)
		return C1, c2, c3, nil
	case byte(0x30):
		return parseCiphertextASN1(c, ciphertext)
	default:
		return nil, nil, nil, errors.New("sm2: invalid/unsupport ciphertext format")
	}
}

func parseCiphertextC2C3(ciphertext []byte, order ciphertextSplicingOrder) ([]byte, []byte) {
	if order == C1C3C2 {
		return ciphertext[SM3_Size:], ciphertext[:SM3_Size]
	}
	return ciphertext[:len(ciphertext)-SM3_Size], ciphertext[len(ciphertext)-SM3_Size:]
}

func unmarshalASN1Ciphertext(ciphertext []byte) (*big.Int, *big.Int, []byte, []byte, error) {
	var (
		x1, y1 = &big.Int{}, &big.Int{}
		c2, c3 []byte
		inner  String
	)
	input := String(ciphertext)
	if !input.ReadASN1(&inner, SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(x1) ||
		!inner.ReadASN1Integer(y1) ||
		!inner.ReadASN1Bytes(&c3, OCTET_STRING) ||
		!inner.ReadASN1Bytes(&c2, OCTET_STRING) ||
		!inner.Empty() {
		return nil, nil, nil, nil, errors.New("sm2: invalid asn1 format ciphertext")
	}
	return x1, y1, c2, c3, nil
}

func parseCiphertextASN1(c *sm2Curve, ciphertext []byte) (*SM2P256Point, []byte, []byte, error) {
	x1, y1, c2, c3, err := unmarshalASN1Ciphertext(ciphertext)
	if err != nil {
		return nil, nil, nil, err
	}
	C1, err := c.pointFromAffine(x1, y1)
	if err != nil {
		return nil, nil, nil, err
	}
	return C1, c2, c3, nil
}

var defaultUID = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}

// CalculateZA ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA).
// Compliance with GB/T 32918.2-2016 5.5.
//
// This function will not use default UID even the uid argument is empty.
func CalculateZA(pub *ecdsa.PublicKey, uid []byte) ([]byte, error) {
	uidLen := len(uid)
	if uidLen >= 0x2000 {
		return nil, errors.New("sm2: the uid is too long")
	}
	entla := uint16(uidLen) << 3
	md := NewSM3()
	md.Write([]byte{byte(entla >> 8), byte(entla)})
	if uidLen > 0 {
		md.Write(uid)
	}
	a := new(big.Int).Sub(pub.Params().P, big.NewInt(3))
	md.Write(toBytes(pub.Curve, a))
	md.Write(toBytes(pub.Curve, pub.Params().B))
	md.Write(toBytes(pub.Curve, pub.Params().Gx))
	md.Write(toBytes(pub.Curve, pub.Params().Gy))
	md.Write(toBytes(pub.Curve, pub.X))
	md.Write(toBytes(pub.Curve, pub.Y))
	return md.Sum(nil), nil
}

// CalculateSM2Hash calculates hash value for data including uid and public key parameters
// according standards.
//
// uid can be nil, then it will use default uid (1234567812345678)
func CalculateSM2Hash(pub *ecdsa.PublicKey, data, uid []byte) ([]byte, error) {
	if len(uid) == 0 {
		uid = defaultUID
	}
	za, err := CalculateZA(pub, uid)
	if err != nil {
		return nil, err
	}
	md := NewSM3()
	md.Write(za)
	md.Write(data)
	return md.Sum(nil), nil
}

// SignASN1 signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the ASN.1 encoded signature.
//
// The signature is randomized. Most applications should use [crypto/rand.Reader]
// as rand. Note that the returned signature does not depend deterministically on
// the bytes read from rand, and may change between calls and/or between versions.
//
// If the opts argument is instance of [*SM2SignerOption], and its ForceGMSign is true,
// then the hash will be treated as raw message.
func SignASN1(rand io.Reader, priv *PrivateKey, hash []byte, opts crypto.SignerOpts) ([]byte, error) {
	if sm2Opts, ok := opts.(*SM2SignerOption); ok && sm2Opts.forceGMSign {
		newHash, err := CalculateSM2Hash(&priv.PublicKey, hash, sm2Opts.uid)
		if err != nil {
			return nil, err
		}
		hash = newHash
	}

	MaybeReadByte(rand)

	switch priv.Curve.Params() {
	case P256().Params():
		return signSM2EC(p256(), priv, rand, hash)
	default:
		return signLegacy(priv, rand, hash)
	}
}

func (priv *PrivateKey) inverseOfPrivateKeyPlus1(c *sm2Curve) (*Nat, error) {
	var (
		err            error
		dp1Inv, oneNat *Nat
		dp1Bytes       []byte
	)
	priv.inverseOfKeyPlus1Once.Do(func() {
		oneNat, _ = NewNat().SetBytes(one.Bytes(), c.N)
		dp1Inv, err = NewNat().SetBytes(priv.D.Bytes(), c.N)
		if err == nil {
			dp1Inv.Add(oneNat, c.N)
			if dp1Inv.IsZero() == 1 { // make sure private key is NOT N-1
				err = errInvalidPrivateKey
			} else {
				dp1Bytes, err = P256OrdInverse(dp1Inv.Bytes(c.N))
				if err == nil {
					priv.inverseOfKeyPlus1, err = NewNat().SetBytes(dp1Bytes, c.N)
				}
			}
		}
	})
	if err != nil {
		return nil, errInvalidPrivateKey
	}
	return priv.inverseOfKeyPlus1, nil
}

func signSM2EC(c *sm2Curve, priv *PrivateKey, rand io.Reader, hash []byte) (sig []byte, err error) {
	// dp1Inv = (d+1)⁻¹
	dp1Inv, err := priv.inverseOfPrivateKeyPlus1(c)
	if err != nil {
		return nil, err
	}

	var (
		k, r, s *Nat
		R       *SM2P256Point
	)

	// hash to int
	e := NewNat()
	hashToNat(c, e, hash)

	for {
		for {
			k, R, err = randomPoint(c, rand, false)
			if err != nil {
				return nil, err
			}
			Rx, err := R.BytesX()
			if err != nil {
				return nil, err
			}
			r, err = NewNat().SetOverflowingBytes(Rx, c.N)
			if err != nil {
				return nil, err
			}

			// r = [Rx + e]
			r.Add(e, c.N)

			// checks if r is zero or [r+k] is zero
			if r.IsZero() == 0 {
				t := NewNat().Set(k).Add(r, c.N)
				if t.IsZero() == 0 {
					break
				}
			}
		}
		// s = [r * d]
		s, err = NewNat().SetBytes(priv.D.Bytes(), c.N)
		if err != nil {
			return nil, err
		}
		s.Mul(r, c.N)
		// k = [k - s]
		k.Sub(s, c.N)
		// k = [(d+1)⁻¹ * (k - r * d)]
		k.Mul(dp1Inv, c.N)
		if k.IsZero() == 0 {
			break
		}
	}

	return encodeSignature(r.Bytes(c.N), k.Bytes(c.N))
}

func encodeSignature(r, s []byte) ([]byte, error) {
	var b Builder
	b.AddASN1(SEQUENCE, func(b *Builder) {
		addASN1IntBytes(b, r)
		addASN1IntBytes(b, s)
	})
	return b.Bytes()
}

// addASN1IntBytes encodes in ASN.1 a positive integer represented as
// a big-endian byte slice with zero or more leading zeroes.
func addASN1IntBytes(b *Builder, bytes []byte) {
	for len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	if len(bytes) == 0 {
		b.SetError(errors.New("invalid integer"))
		return
	}
	b.AddASN1(INTEGER, func(c *Builder) {
		if bytes[0]&0x80 != 0 {
			c.AddUint8(0)
		}
		c.AddBytes(bytes)
	})
}

var ErrInvalidSignature = errors.New("sm2: invalid signature")

// RecoverPublicKeysFromSM2Signature recovers two or four SM2 public keys from a given signature and hash.
// It takes the hash and signature as input and returns the recovered public keys as []*ecdsa.PublicKey.
// If the signature or hash is invalid, it returns an error.
// The function follows the SM2 algorithm to recover the public keys.
func RecoverPublicKeysFromSM2Signature(hash, sig []byte) ([]*ecdsa.PublicKey, error) {
	c := p256()
	rBytes, sBytes, err := parseSignature(sig)
	if err != nil {
		return nil, err
	}
	r, err := NewNat().SetBytes(rBytes, c.N)
	if err != nil || r.IsZero() == 1 {
		return nil, ErrInvalidSignature
	}
	s, err := NewNat().SetBytes(sBytes, c.N)
	if err != nil || s.IsZero() == 1 {
		return nil, ErrInvalidSignature
	}

	e := NewNat()
	hashToNat(c, e, hash)

	// p₁ = [-s]G
	negS := NewNat().ExpandFor(c.N).Sub(s, c.N)
	p1, err := c.newPoint().ScalarBaseMult(negS.Bytes(c.N))
	if err != nil {
		return nil, err
	}

	// s = [r + s]
	s.Add(r, c.N)
	if s.IsZero() == 1 {
		return nil, ErrInvalidSignature
	}
	// sBytes = (r+s)⁻¹
	sBytes, err = P256OrdInverse(s.Bytes(c.N))
	if err != nil {
		return nil, err
	}

	// r = (Rx + e) mod N
	// Rx = r - e
	r.Sub(e, c.N)
	if r.IsZero() == 1 {
		return nil, ErrInvalidSignature
	}
	pointRx := make([]*Nat, 0, 2)
	pointRx = append(pointRx, r)
	// check if Rx in (N, P), small probability event
	s.Set(r)
	s = s.Add(c.N.Nat(), c.P)
	if s.CmpGeq(c.N.Nat()) == 1 {
		pointRx = append(pointRx, s)
	}
	pubs := make([]*ecdsa.PublicKey, 0, 4)
	bytes := make([]byte, len(rBytes)+1)
	compressFlags := []byte{sm2_compressed02, sm2_compressed03}
	// Rx has one or two possible values, so point R has two or four possible values
	for _, x := range pointRx {
		rBytes = x.Bytes(c.N)
		copy(bytes[1:], rBytes)
		for _, flag := range compressFlags {
			bytes[0] = flag
			// p0 = R
			p0, err := c.newPoint().SetBytes(bytes)
			if err != nil {
				return nil, err
			}
			// p0 = R - [s]G
			p0.Add(p0, p1)
			// Pub = [(r + s)⁻¹](R - [s]G)
			p0.ScalarMult(p0, sBytes)
			pub := new(ecdsa.PublicKey)
			pub.Curve = c.curve
			pub.X, pub.Y, err = c.pointToAffine(p0)
			if err != nil {
				return nil, err
			}
			pubs = append(pubs, pub)
		}
	}

	return pubs, nil
}

// VerifyASN1 verifies the ASN.1 encoded signature, sig, of hash using the
// public key, pub. Its return value records whether the signature is valid.
//
// Compliance with GB/T 32918.2-2016 regardless it's SM2 curve or not.
// Caller should make sure the hash's correctness, in other words,
// the caller must pre-calculate the hash value.
func VerifyASN1(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	switch pub.Curve.Params() {
	case P256().Params():
		return verifySM2EC(p256(), pub, hash, sig)
	default:
		return verifyLegacy(pub, hash, sig)
	}
}

func verifySM2EC(c *sm2Curve, pub *ecdsa.PublicKey, hash, sig []byte) bool {
	rBytes, sBytes, err := parseSignature(sig)
	if err != nil {
		return false
	}

	Q, err := c.pointFromAffine(pub.X, pub.Y)
	if err != nil {
		return false
	}

	r, err := NewNat().SetBytes(rBytes, c.N)
	if err != nil || r.IsZero() == 1 {
		return false
	}
	s, err := NewNat().SetBytes(sBytes, c.N)
	if err != nil || s.IsZero() == 1 {
		return false
	}

	e := NewNat()
	hashToNat(c, e, hash)

	// p₁ = [s]G
	p1, err := c.newPoint().ScalarBaseMult(s.Bytes(c.N))
	if err != nil {
		return false
	}

	// s = [r + s]
	s.Add(r, c.N)
	if s.IsZero() == 1 {
		return false
	}

	// p₂ = [r+s]Q
	p2, err := Q.ScalarMult(Q, s.Bytes(c.N))
	if err != nil {
		return false
	}

	// BytesX returns an error for the point at infinity.
	Rx, err := p1.Add(p1, p2).BytesX()
	if err != nil {
		return false
	}

	_, err = s.SetOverflowingBytes(Rx, c.N)
	if err != nil {
		return false
	}
	s.Add(e, c.N)

	return s.Equal(r) == 1
}

// VerifyASN1WithSM2 verifies the signature in ASN.1 encoding format sig of raw msg
// and uid using the public key, pub. The uid can be empty, meaning to use the default value.
//
// It returns value records whether the signature is valid. Compliance with GB/T 32918.2-2016.
func VerifyASN1WithSM2(pub *ecdsa.PublicKey, uid, msg, sig []byte) bool {
	digest, err := CalculateSM2Hash(pub, msg, uid)
	if err != nil {
		return false
	}
	return VerifyASN1(pub, digest, sig)
}

func parseSignature(sig []byte) (r, s []byte, err error) {
	var inner String
	input := String(sig)
	if !input.ReadASN1(&inner, SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(&r) ||
		!inner.ReadASN1Integer(&s) ||
		!inner.Empty() {
		return nil, nil, errors.New("invalid ASN.1")
	}
	return r, s, nil
}

// hashToNat sets e to the left-most bits of hash, according to
// SEC 1, Section 4.1.3, point 5 and Section 4.1.4, point 3.
func hashToNat(c *sm2Curve, e *Nat, hash []byte) {
	// ECDSA asks us to take the left-most log2(N) bits of hash, and use them as
	// an integer modulo N. This is the absolute worst of all worlds: we still
	// have to reduce, because the result might still overflow N, but to take
	// the left-most bits for P-521 we have to do a right shift.
	if size := c.N.Size(); len(hash) > size {
		hash = hash[:size]
		if excess := len(hash)*8 - c.N.BitLen(); excess > 0 {
			hash = append([]byte{}, hash...)
			for i := len(hash) - 1; i >= 0; i-- {
				hash[i] >>= excess
				if i > 0 {
					hash[i] |= hash[i-1] << (8 - excess)
				}
			}
		}
	}
	_, err := e.SetOverflowingBytes(hash, c.N)
	if err != nil {
		panic("sm2: internal error: truncated hash is too long")
	}
}

// IsSM2PublicKey check if given public key is a SM2 public key or not
func IsSM2PublicKey(publicKey any) bool {
	pub, ok := publicKey.(*ecdsa.PublicKey)
	return ok && pub.Curve == P256()
}

// P256 returns sm2 curve signleton, this function is for backward compatibility.
func P256() elliptic.Curve {
	return sm2ecP256()
}

// PublicKeyToECDH returns k as a [ecdh.PublicKey]. It returns an error if the key is
// invalid according to the definition of [ecdh.Curve.NewPublicKey], or if the
// Curve is not supported by ecdh.
func PublicKeyToECDH(k *ecdsa.PublicKey) (*ecdh.PublicKey, error) {
	c := curveToECDH(k.Curve)
	if c == nil {
		return nil, errors.New("sm2: unsupported curve by ecdh")
	}
	if !k.Curve.IsOnCurve(k.X, k.Y) {
		return nil, errors.New("sm2: invalid public key")
	}
	return c.NewPublicKey(elliptic.Marshal(k.Curve, k.X, k.Y))
}

// ECDH returns k as a [ecdh.PrivateKey]. It returns an error if the key is
// invalid according to the definition of [ecdh.Curve.NewPrivateKey], or if the
// Curve is not supported by ecdh.
func (k *PrivateKey) ECDH() (*ecdh.PrivateKey, error) {
	c := curveToECDH(k.Curve)
	if c == nil {
		return nil, errors.New("sm2: unsupported curve by ecdh")
	}
	size := (k.Curve.Params().N.BitLen() + 7) / 8
	if k.D.BitLen() > size*8 {
		return nil, errors.New("sm2: invalid private key")
	}
	return c.NewPrivateKey(k.D.FillBytes(make([]byte, size)))
}

func curveToECDH(c elliptic.Curve) ecdh.Curve {
	switch c {
	case P256():
		return ecdh.P256()
	default:
		return nil
	}
}

// randomPoint returns a random scalar and the corresponding point using the
// procedure given in FIPS 186-4, Appendix B.5.2 (rejection sampling).
func randomPoint(c *sm2Curve, rand io.Reader, checkOrderMinus1 bool) (k *Nat, p *SM2P256Point, err error) {
	k = NewNat()
	for {
		b := make([]byte, c.N.Size())
		if _, err = io.ReadFull(rand, b); err != nil {
			return
		}

		// Mask off any excess bits to increase the chance of hitting a value in
		// (0, N). These are the most dangerous lines in the package and maybe in
		// the library: a single bit of bias in the selection of nonces would likely
		// lead to key recovery, but no tests would fail. Look but DO NOT TOUCH.
		if excess := len(b)*8 - c.N.BitLen(); excess > 0 {
			// Just to be safe, assert that this only happens for the one curve that
			// doesn't have a round number of bits.
			if excess != 0 {
				panic("sm2: internal error: unexpectedly masking off bits")
			}
			b[0] >>= excess
		}

		// Checking 0 < k <= N - 2.
		// None of this matters anyway because the chance of selecting
		// zero is cryptographically negligible.
		if _, err = k.SetBytes(b, c.N); err == nil && k.IsZero() == 0 && (!checkOrderMinus1 || k.Equal(c.nMinus1) == 0) {
			break
		}

		if testingOnlyRejectionSamplingLooped != nil {
			testingOnlyRejectionSamplingLooped()
		}
	}

	p, err = c.newPoint().ScalarBaseMult(k.Bytes(c.N))
	return
}

// testingOnlyRejectionSamplingLooped is called when rejection sampling in
// randomPoint rejects a candidate for being higher than the modulus.
var testingOnlyRejectionSamplingLooped func()

type sm2Curve struct {
	newPoint func() *SM2P256Point
	curve    elliptic.Curve
	N        *Modulus
	P        *Modulus
	nMinus1  *Nat
	nMinus2  []byte
}

// pointFromAffine is used to convert the PublicKey to a sm2 Point.
func (curve *sm2Curve) pointFromAffine(x, y *big.Int) (p *SM2P256Point, err error) {
	bitSize := curve.curve.Params().BitSize
	// Reject values that would not get correctly encoded.
	if x.Sign() < 0 || y.Sign() < 0 {
		return p, errors.New("negative coordinate")
	}
	if x.BitLen() > bitSize || y.BitLen() > bitSize {
		return p, errors.New("overflowing coordinate")
	}
	// Encode the coordinates and let SetBytes reject invalid points.
	byteLen := (bitSize + 7) / 8
	buf := make([]byte, 1+2*byteLen)
	buf[0] = 4 // uncompressed point
	x.FillBytes(buf[1 : 1+byteLen])
	y.FillBytes(buf[1+byteLen : 1+2*byteLen])
	return curve.newPoint().SetBytes(buf)
}

// pointToAffine is used to convert a sm2 Point to a PublicKey.
func (curve *sm2Curve) pointToAffine(p *SM2P256Point) (x, y *big.Int, err error) {
	out := p.Bytes()
	if len(out) == 1 && out[0] == 0 {
		// This is the encoding of the point at infinity.
		return nil, nil, errors.New("sm2: public key point is the infinity")
	}
	byteLen := (curve.curve.Params().BitSize + 7) / 8
	x = new(big.Int).SetBytes(out[1 : 1+byteLen])
	y = new(big.Int).SetBytes(out[1+byteLen:])
	return x, y, nil
}

var p256Once sync.Once
var _p256 *sm2Curve

func p256() *sm2Curve {
	p256Once.Do(func() {
		_p256 = &sm2Curve{
			newPoint: func() *SM2P256Point { return NewSM2P256Point() },
		}
		precomputeParams(_p256, P256())
	})
	return _p256
}

func precomputeParams(c *sm2Curve, curve elliptic.Curve) {
	params := curve.Params()
	c.curve = curve
	c.N, _ = NewModulusFromBig(params.N)
	c.P, _ = NewModulusFromBig(params.P)
	c.nMinus2 = new(big.Int).Sub(params.N, big.NewInt(2)).Bytes()
	c.nMinus1, _ = NewNat().SetBytes(new(big.Int).Sub(params.N, big.NewInt(1)).Bytes(), c.N)
}

var errInvalidPrivateKey = errors.New("sm2: invalid private key")

// This file contains a math/big implementation of SM2 DSA/Encryption that is only used for
// deprecated custom curves.

// A invertible implements fast inverse in GF(N).
type invertible interface {
	// Inverse returns the inverse of k mod Params().N.
	Inverse(k *big.Int) *big.Int
}

// A combinedMult implements fast combined multiplication for verification.
type combinedMult interface {
	// CombinedMult returns [s1]G + [s2]P where G is the generator.
	CombinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x, y *big.Int)
}

// hashToInt converts a hash value to an integer. Per FIPS 186-4, Section 6.4,
// we use the left-most bits of the hash to match the bit-length of the order of
// the curve. This also performs Step 5 of SEC 1, Version 2.0, Section 4.1.3.
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

var errZeroParam = errors.New("zero parameter")

// Sign signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the signature as a pair of integers. Most applications should use
// SignASN1 instead of dealing directly with r, s.
//
// Compliance with GB/T 32918.2-2016 regardless it's SM2 curve or not.
func Sign(rand io.Reader, priv *ecdsa.PrivateKey, hash []byte) (r, s *big.Int, err error) {
	key := new(PrivateKey)
	key.PrivateKey = *priv
	sig, err := SignASN1(rand, key, hash, nil)
	if err != nil {
		return nil, nil, err
	}

	r, s = new(big.Int), new(big.Int)
	var inner String
	input := String(sig)
	if !input.ReadASN1(&inner, SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		return nil, nil, errors.New("invalid ASN.1 from SignASN1")
	}
	return r, s, nil
}

func signLegacy(priv *PrivateKey, rand io.Reader, hash []byte) (sig []byte, err error) {
	// See [NSA] 3.4.1
	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, errZeroParam
	}
	var k, r, s *big.Int
	e := hashToInt(hash, c)
	for {
		for {
			k, err = randFieldElement(c, rand)
			if err != nil {
				return nil, err
			}

			r, _ = priv.Curve.ScalarBaseMult(k.Bytes()) // (x, y) = k*G
			r.Add(r, e)                                 // r = x + e
			r.Mod(r, N)                                 // r = (x + e) mod N
			if r.Sign() != 0 {
				t := new(big.Int).Add(r, k)
				if t.Cmp(N) != 0 { // if r != 0 && (r + k) != N then ok
					break
				}
			}
		}
		s = new(big.Int).Mul(priv.D, r)
		s = new(big.Int).Sub(k, s)
		dp1 := new(big.Int).Add(priv.D, one)

		var dp1Inv *big.Int

		if in, ok := priv.Curve.(invertible); ok {
			dp1Inv = in.Inverse(dp1)
		} else {
			dp1Inv = fermatInverse(dp1, N) // N != 0
		}

		s.Mul(s, dp1Inv)
		s.Mod(s, N) // N != 0
		if s.Sign() != 0 {
			break
		}
	}

	return encodeSignature(r.Bytes(), s.Bytes())
}

// fermatInverse calculates the inverse of k in GF(P) using Fermat's method
// (exponentiation modulo P - 2, per Euler's theorem). This has better
// constant-time properties than Euclid's method (implemented in
// math/big.Int.ModInverse and FIPS 186-4, Appendix C.1) although math/big
// itself isn't strictly constant-time so it's not perfect.
func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
}

// SignWithSM2 follow sm2 dsa standards for hash part, compliance with GB/T 32918.2-2016.
func SignWithSM2(rand io.Reader, priv *ecdsa.PrivateKey, uid, msg []byte) (r, s *big.Int, err error) {
	digest, err := CalculateSM2Hash(&priv.PublicKey, msg, uid)
	if err != nil {
		return nil, nil, err
	}

	return Sign(rand, priv, digest)
}

// Verify verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid. Most applications should
// use VerifyASN1 instead of dealing directly with r, s.
//
// Compliance with GB/T 32918.2-2016 regardless it's SM2 curve or not.
// Caller should make sure the hash's correctness.
func Verify(pub *ecdsa.PublicKey, hash []byte, r, s *big.Int) bool {
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	sig, err := encodeSignature(r.Bytes(), s.Bytes())
	if err != nil {
		return false
	}
	return VerifyASN1(pub, hash, sig)
}

func verifyLegacy(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	rBytes, sBytes, err := parseSignature(sig)
	if err != nil {
		return false
	}
	r, s := new(big.Int).SetBytes(rBytes), new(big.Int).SetBytes(sBytes)

	c := pub.Curve
	N := c.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}
	e := hashToInt(hash, c)
	t := new(big.Int).Add(r, s)
	t.Mod(t, N)
	if t.Sign() == 0 {
		return false
	}

	var x *big.Int
	if opt, ok := c.(combinedMult); ok {
		x, _ = opt.CombinedMult(pub.X, pub.Y, s.Bytes(), t.Bytes())
	} else {
		x1, y1 := c.ScalarBaseMult(s.Bytes())
		x2, y2 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
		x, _ = c.Add(x1, y1, x2, y2)
	}

	x.Add(x, e)
	x.Mod(x, N)
	return x.Cmp(r) == 0
}

// VerifyWithSM2 verifies the signature in r, s of raw msg and uid using the public key, pub.
// It returns value records whether the signature is valid. Compliance with GB/T 32918.2-2016.
func VerifyWithSM2(pub *ecdsa.PublicKey, uid, msg []byte, r, s *big.Int) bool {
	digest, err := CalculateSM2Hash(pub, msg, uid)
	if err != nil {
		return false
	}
	return Verify(pub, digest, r, s)
}

var (
	one = new(big.Int).SetInt64(1)
)

// randFieldElement returns a random element of the order of the given
// curve using the procedure given in FIPS 186-4, Appendix B.5.2.
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	// See randomPoint for notes on the algorithm. This has to match, or s390x
	// signatures will come out different from other architectures, which will
	// break TLS recorded tests.
	for {
		N := c.Params().N
		b := make([]byte, (N.BitLen()+7)/8)
		if _, err = io.ReadFull(rand, b); err != nil {
			return
		}
		if excess := len(b)*8 - N.BitLen(); excess > 0 {
			b[0] >>= excess
		}
		k = new(big.Int).SetBytes(b)
		if k.Sign() != 0 && k.Cmp(N) < 0 {
			return
		}
	}
}

func encryptLegacy(random io.Reader, pub *ecdsa.PublicKey, msg []byte, opts *EncrypterOpts) ([]byte, error) {
	curve := pub.Curve
	msgLen := len(msg)

	var retryCount int = 0
	for {
		//A1, generate random k
		k, err := randFieldElement(curve, random)
		if err != nil {
			return nil, err
		}

		//A2, calculate C1 = k * G
		x1, y1 := curve.ScalarBaseMult(k.Bytes())
		c1 := opts.pointMarshalMode.mashal(curve, x1, y1)

		//A4, calculate k * P (point of Public Key)
		x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())

		//A5, calculate t=KDF(x2||y2, klen)
		c2 := SM3_Kdf(append(toBytes(curve, x2), toBytes(curve, y2)...), msgLen)
		if ConstantTimeAllZero(c2) == 1 {
			retryCount++
			if retryCount > maxRetryLimit {
				return nil, fmt.Errorf("sm2: A5, failed to calculate valid t, tried %v times", retryCount)
			}
			continue
		}

		//A6, C2 = M + t;
		XORBytes(c2, msg, c2)

		//A7, C3 = hash(x2||M||y2)
		c3 := calculateC3(curve, x2, y2, msg)

		if opts.ciphertextEncoding == ENCODING_PLAIN {
			if opts.ciphertextSplicingOrder == C1C3C2 {
				// c1 || c3 || c2
				return append(append(c1, c3...), c2...), nil
			}
			// c1 || c2 || c3
			return append(append(c1, c2...), c3...), nil
		}
		// ASN.1 format will force C3 C2 order
		return mashalASN1Ciphertext(x1, y1, c2, c3)
	}
}

func calculateC3(curve elliptic.Curve, x2, y2 *big.Int, msg []byte) []byte {
	md := NewSM3()
	md.Write(toBytes(curve, x2))
	md.Write(msg)
	md.Write(toBytes(curve, y2))
	return md.Sum(nil)
}

func mashalASN1Ciphertext(x1, y1 *big.Int, c2, c3 []byte) ([]byte, error) {
	var b Builder
	b.AddASN1(SEQUENCE, func(b *Builder) {
		b.AddASN1BigInt(x1)
		b.AddASN1BigInt(y1)
		b.AddASN1OctetString(c3)
		b.AddASN1OctetString(c2)
	})
	return b.Bytes()
}

// ASN1Ciphertext2Plain utility method to convert ASN.1 encoding ciphertext to plain encoding format
func ASN1Ciphertext2Plain(ciphertext []byte, opts *EncrypterOpts) ([]byte, error) {
	if opts == nil {
		opts = defaultEncrypterOpts
	}
	x1, y1, c2, c3, err := unmarshalASN1Ciphertext((ciphertext))
	if err != nil {
		return nil, err
	}
	curve := P256()
	c1 := opts.pointMarshalMode.mashal(curve, x1, y1)
	if opts.ciphertextSplicingOrder == C1C3C2 {
		// c1 || c3 || c2
		return append(append(c1, c3...), c2...), nil
	}
	// c1 || c2 || c3
	return append(append(c1, c2...), c3...), nil
}

// PlainCiphertext2ASN1 utility method to convert plain encoding ciphertext to ASN.1 encoding format
func PlainCiphertext2ASN1(ciphertext []byte, from ciphertextSplicingOrder) ([]byte, error) {
	if ciphertext[0] == 0x30 {
		return nil, errors.New("sm2: invalid plain encoding ciphertext")
	}
	curve := P256()
	ciphertextLen := len(ciphertext)
	if ciphertextLen <= 1+(curve.Params().BitSize/8)+SM3_Size {
		return nil, errCiphertextTooShort
	}
	// get C1, and check C1
	x1, y1, c3Start, err := bytes2Point(curve, ciphertext)
	if err != nil {
		return nil, err
	}

	var c2, c3 []byte

	if from == C1C3C2 {
		c2 = ciphertext[c3Start+SM3_Size:]
		c3 = ciphertext[c3Start : c3Start+SM3_Size]
	} else {
		c2 = ciphertext[c3Start : ciphertextLen-SM3_Size]
		c3 = ciphertext[ciphertextLen-SM3_Size:]
	}
	return mashalASN1Ciphertext(x1, y1, c2, c3)
}

// AdjustCiphertextSplicingOrder utility method to change c2 c3 order
func AdjustCiphertextSplicingOrder(ciphertext []byte, from, to ciphertextSplicingOrder) ([]byte, error) {
	curve := P256()
	if from == to {
		return ciphertext, nil
	}
	ciphertextLen := len(ciphertext)
	if ciphertextLen <= 1+(curve.Params().BitSize/8)+SM3_Size {
		return nil, errCiphertextTooShort
	}

	// get C1, and check C1
	_, _, c3Start, err := bytes2Point(curve, ciphertext)
	if err != nil {
		return nil, err
	}

	var c1, c2, c3 []byte

	c1 = ciphertext[:c3Start]
	if from == C1C3C2 {
		c2 = ciphertext[c3Start+SM3_Size:]
		c3 = ciphertext[c3Start : c3Start+SM3_Size]
	} else {
		c2 = ciphertext[c3Start : ciphertextLen-SM3_Size]
		c3 = ciphertext[ciphertextLen-SM3_Size:]
	}

	result := make([]byte, ciphertextLen)
	copy(result, c1)
	if to == C1C3C2 {
		// c1 || c3 || c2
		copy(result[c3Start:], c3)
		copy(result[c3Start+SM3_Size:], c2)
	} else {
		// c1 || c2 || c3
		copy(result[c3Start:], c2)
		copy(result[ciphertextLen-SM3_Size:], c3)
	}
	return result, nil
}

func decryptASN1(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	x1, y1, c2, c3, err := unmarshalASN1Ciphertext(ciphertext)
	if err != nil {
		return nil, ErrDecryption
	}
	return rawDecrypt(priv, x1, y1, c2, c3)
}

func rawDecrypt(priv *PrivateKey, x1, y1 *big.Int, c2, c3 []byte) ([]byte, error) {
	curve := priv.Curve
	x2, y2 := curve.ScalarMult(x1, y1, priv.D.Bytes())
	msgLen := len(c2)
	msg := SM3_Kdf(append(toBytes(curve, x2), toBytes(curve, y2)...), msgLen)
	if ConstantTimeAllZero(c2) == 1 {
		return nil, ErrDecryption
	}

	//B5, calculate msg = c2 ^ t
	XORBytes(msg, c2, msg)

	u := calculateC3(curve, x2, y2, msg)
	if subtle.ConstantTimeCompare(u, c3) == 1 {
		return msg, nil
	}
	return nil, ErrDecryption
}

func decryptLegacy(priv *PrivateKey, ciphertext []byte, opts *DecrypterOpts) ([]byte, error) {
	splicingOrder := C1C3C2
	if opts != nil {
		if opts.ciphertextEncoding == ENCODING_ASN1 {
			return decryptASN1(priv, ciphertext)
		}
		splicingOrder = opts.cipherTextSplicingOrder
	}
	if ciphertext[0] == 0x30 {
		return decryptASN1(priv, ciphertext)
	}
	ciphertextLen := len(ciphertext)
	curve := priv.Curve
	// B1, get C1, and check C1
	x1, y1, c3Start, err := bytes2Point(curve, ciphertext)
	if err != nil {
		return nil, ErrDecryption
	}

	//B4, calculate t=KDF(x2||y2, klen)
	var c2, c3 []byte
	if splicingOrder == C1C3C2 {
		c2 = ciphertext[c3Start+SM3_Size:]
		c3 = ciphertext[c3Start : c3Start+SM3_Size]
	} else {
		c2 = ciphertext[c3Start : ciphertextLen-SM3_Size]
		c3 = ciphertext[ciphertextLen-SM3_Size:]
	}

	return rawDecrypt(priv, x1, y1, c2, c3)
}

func bytes2Point(curve elliptic.Curve, bytes []byte) (*big.Int, *big.Int, int, error) {
	if len(bytes) < 1+(curve.Params().BitSize/8) {
		return nil, nil, 0, fmt.Errorf("sm2: invalid bytes length %d", len(bytes))
	}
	format := bytes[0]
	byteLen := (curve.Params().BitSize + 7) >> 3
	switch format {
	case sm2_uncompressed, sm2_hybrid06, sm2_hybrid07: // what's the hybrid format purpose?
		if len(bytes) < 1+byteLen*2 {
			return nil, nil, 0, fmt.Errorf("sm2: invalid point uncompressed/hybrid form bytes length %d", len(bytes))
		}
		data := make([]byte, 1+byteLen*2)
		data[0] = sm2_uncompressed
		copy(data[1:], bytes[1:1+byteLen*2])
		x, y := Unmarshal(curve, data)
		if x == nil || y == nil {
			return nil, nil, 0, fmt.Errorf("sm2: point is not on curve %s", curve.Params().Name)
		}
		return x, y, 1 + byteLen*2, nil
	case sm2_compressed02, sm2_compressed03:
		if len(bytes) < 1+byteLen {
			return nil, nil, 0, fmt.Errorf("sm2: invalid point compressed form bytes length %d", len(bytes))
		}
		// Make sure it's NIST curve or SM2 P-256 curve
		if strings.HasPrefix(curve.Params().Name, "P-") || strings.EqualFold(curve.Params().Name, P256().Params().Name) {
			// y² = x³ - 3x + b, prime curves
			x, y := UnmarshalCompressed(curve, bytes[:1+byteLen])
			if x == nil || y == nil {
				return nil, nil, 0, fmt.Errorf("sm2: point is not on curve %s", curve.Params().Name)
			}
			return x, y, 1 + byteLen, nil
		}
		return nil, nil, 0, fmt.Errorf("sm2: unsupport point form %d, curve %s", format, curve.Params().Name)
	}
	return nil, nil, 0, fmt.Errorf("sm2: unknown point form %d", format)
}

func (mode pointMarshalMode) mashal(curve elliptic.Curve, x, y *big.Int) []byte {
	switch mode {
	case MarshalCompressed:
		return elliptic.MarshalCompressed(curve, x, y)
	case MarshalHybrid:
		buffer := elliptic.Marshal(curve, x, y)
		buffer[0] = byte(y.Bit(0)) | sm2_hybrid06
		return buffer
	default:
		return elliptic.Marshal(curve, x, y)
	}
}

// This file contains a math/big implementation of SM2 key exchange which is deprecated, please use ecdh instead.

// KeyExchange key exchange struct, include internal stat in whole key exchange flow.
// Initiator's flow will be: NewKeyExchange -> InitKeyExchange -> transmission -> ConfirmResponder
// Responder's flow will be: NewKeyExchange -> waiting ... -> RepondKeyExchange -> transmission -> ConfirmInitiator
type KeyExchange struct {
	genSignature bool             // control the optional sign/verify step triggered by responsder
	keyLength    int              // key length
	privateKey   *PrivateKey      // owner's encryption private key
	z            []byte           // owner identifiable id
	peerPub      *ecdsa.PublicKey // peer public key
	peerZ        []byte           // peer identifiable id
	r            *big.Int         // Ephemeral Private Key, random which will be used to compute secret
	secret       *ecdsa.PublicKey // Ephemeral Public Key, generated secret which will be passed to peer
	peerSecret   *ecdsa.PublicKey // received peer's secret, Ephemeral Public Key
	w2           *big.Int         // internal state which will be used when compute the key and signature, 2^w
	w2Minus1     *big.Int         // internal state which will be used when compute the key and signature, 2^w – 1
	v            *ecdsa.PublicKey // internal state which will be used when compute the key and signature, u/v
}

func destroyBigInt(n *big.Int) {
	if n != nil {
		n.SetInt64(0)
	}
}

func destroyPublicKey(pub *ecdsa.PublicKey) {
	if pub != nil {
		destroyBigInt(pub.X)
		destroyBigInt(pub.Y)
	}
}

func destroyBytes(bytes []byte) {
	for v := range bytes {
		bytes[v] = 0
	}
}

// Destroy clear all internal state and Ephemeral private/public keys.
func (ke *KeyExchange) Destroy() {
	destroyBytes(ke.z)
	destroyBytes(ke.peerZ)
	destroyBigInt(ke.r)
	destroyPublicKey(ke.v)
}

// NewKeyExchange create one new KeyExchange object
//
// 在部分场景中，在初始  KeyExchange 时暂时没有对端的公开信息（如公钥、UID），这些信息可能需要在后续的交换中得到。
// 这种情况下，可设置 peerPub、peerUID 参数为 nil，并在合适的时候通过 KeyExchange.SetPeerParameters 方法配置相关参数。
// 注意 KeyExchange.SetPeerParameters 方法必须要在 KeyExchange.RepondKeyExchange 或 KeyExchange.RepondKeyExchange 方法之前调用。
func NewKeyExchange(priv *PrivateKey, peerPub *ecdsa.PublicKey, uid, peerUID []byte, keyLen int, genSignature bool) (ke *KeyExchange, err error) {
	ke = &KeyExchange{}
	ke.genSignature = genSignature

	ke.keyLength = keyLen
	ke.privateKey = priv

	one := big.NewInt(1)
	/* compute w = [log2(n)/2 - 1] = 127 */
	w := (priv.Params().N.BitLen()+1)/2 - 1

	/* w2 = 2^w = 0x80000000000000000000000000000000 */
	ke.w2 = (&big.Int{}).Lsh(one, uint(w))
	/* x2minus1 = 2^w - 1 = 0x7fffffffffffffffffffffffffffffff */
	ke.w2Minus1 = (&big.Int{}).Sub(ke.w2, one)

	if len(uid) == 0 {
		uid = defaultUID
	}
	ke.z, err = CalculateZA(&ke.privateKey.PublicKey, uid)
	if err != nil {
		return nil, err
	}

	err = ke.SetPeerParameters(peerPub, peerUID)
	if err != nil {
		return nil, err
	}

	ke.secret = &ecdsa.PublicKey{}
	ke.secret.Curve = priv.PublicKey.Curve

	ke.v = &ecdsa.PublicKey{}
	ke.v.Curve = priv.PublicKey.Curve

	return
}

// SetPeerParameters 设置对端公开信息，该方法用于某些初期状态无法取得对端公开参数的场景。
// 例如：在TLCP协议中，基于SM2算法ECDHE过程。
//
// 注意该方法仅在 NewKeyExchange 没有提供 peerPub、peerUID参数时允许被调用，
// 且该方法只能调用一次不可重复调用，若多次调用或peerPub、peerUID已经存在则会发生错误。
func (ke *KeyExchange) SetPeerParameters(peerPub *ecdsa.PublicKey, peerUID []byte) error {
	if peerPub == nil {
		return nil
	}
	if len(peerUID) == 0 {
		peerUID = defaultUID
	}
	if ke.peerPub != nil {
		return errors.New("sm2: 'peerPub' already exists, please do not set it")
	}

	if peerPub.Curve != ke.privateKey.Curve {
		return errors.New("sm2: peer public key is not expected/supported")
	}

	var err error
	ke.peerPub = peerPub
	ke.peerZ, err = CalculateZA(ke.peerPub, peerUID)
	if err != nil {
		return err
	}
	ke.peerSecret = &ecdsa.PublicKey{}
	ke.peerSecret.Curve = peerPub.Curve
	return nil
}

func initKeyExchange(ke *KeyExchange, r *big.Int) {
	ke.secret.X, ke.secret.Y = ke.privateKey.ScalarBaseMult(r.Bytes())
	ke.r = r
}

// InitKeyExchange is for initiator's step A1-A3, returns generated Ephemeral Public Key which will be passed to Reponder.
func (ke *KeyExchange) InitKeyExchange(rand io.Reader) (*ecdsa.PublicKey, error) {
	r, err := randFieldElement(ke.privateKey, rand)
	if err != nil {
		return nil, err
	}
	initKeyExchange(ke, r)
	return ke.secret, nil
}

func (ke *KeyExchange) sign(isResponder bool, prefix byte) []byte {
	var buffer []byte
	hash := NewSM3()
	hash.Write(toBytes(ke.privateKey, ke.v.X))
	if isResponder {
		hash.Write(ke.peerZ)
		hash.Write(ke.z)
		hash.Write(toBytes(ke.privateKey, ke.peerSecret.X))
		hash.Write(toBytes(ke.privateKey, ke.peerSecret.Y))
		hash.Write(toBytes(ke.privateKey, ke.secret.X))
		hash.Write(toBytes(ke.privateKey, ke.secret.Y))
	} else {
		hash.Write(ke.z)
		hash.Write(ke.peerZ)
		hash.Write(toBytes(ke.privateKey, ke.secret.X))
		hash.Write(toBytes(ke.privateKey, ke.secret.Y))
		hash.Write(toBytes(ke.privateKey, ke.peerSecret.X))
		hash.Write(toBytes(ke.privateKey, ke.peerSecret.Y))
	}
	buffer = hash.Sum(nil)
	hash.Reset()
	hash.Write([]byte{prefix})
	hash.Write(toBytes(ke.privateKey, ke.v.Y))
	hash.Write(buffer)
	return hash.Sum(nil)
}

func (ke *KeyExchange) generateSharedKey(isResponder bool) ([]byte, error) {
	var buffer []byte
	buffer = append(buffer, toBytes(ke.privateKey, ke.v.X)...)
	buffer = append(buffer, toBytes(ke.privateKey, ke.v.Y)...)
	if isResponder {
		buffer = append(buffer, ke.peerZ...)
		buffer = append(buffer, ke.z...)
	} else {
		buffer = append(buffer, ke.z...)
		buffer = append(buffer, ke.peerZ...)
	}
	return SM3_Kdf(buffer, ke.keyLength), nil
}

// avf is the associative value function.
func (ke *KeyExchange) avf(x *big.Int) *big.Int {
	t := (&big.Int{}).And(ke.w2Minus1, x)
	t.Add(ke.w2, t)
	return t
}

// mqv implements SM2-MQV procedure
func (ke *KeyExchange) mqv() {
	// implicitSig: (sPriv + avf(ePub) * ePriv) mod N
	// Calculate x2`
	t := ke.avf(ke.secret.X)

	// Calculate tB
	t.Mul(t, ke.r)
	t.Add(t, ke.privateKey.D)
	t.Mod(t, ke.privateKey.Params().N)

	// new base point: peerPub + [x1](peerSecret)
	// x1` = 2^w + (x & (2^w – 1))
	x1 := ke.avf(ke.peerSecret.X)
	// Point(x, y) = peerPub + [x1](peerSecret)
	x, y := ke.privateKey.ScalarMult(ke.peerSecret.X, ke.peerSecret.Y, x1.Bytes())
	x, y = ke.privateKey.Add(ke.peerPub.X, ke.peerPub.Y, x, y)

	ke.v.X, ke.v.Y = ke.privateKey.ScalarMult(x, y, t.Bytes())
}

func respondKeyExchange(ke *KeyExchange, rA *ecdsa.PublicKey, r *big.Int) (*ecdsa.PublicKey, []byte, error) {
	if ke.peerPub == nil {
		return nil, nil, errors.New("sm2: no peer public key given")
	}
	if !ke.privateKey.IsOnCurve(rA.X, rA.Y) {
		return nil, nil, errors.New("sm2: invalid initiator's ephemeral public key")
	}
	ke.peerSecret = rA
	// secret = RB = [r]G
	ke.secret.X, ke.secret.Y = ke.privateKey.ScalarBaseMult(r.Bytes())
	ke.r = r

	ke.mqv()
	if ke.v.X.Sign() == 0 && ke.v.Y.Sign() == 0 {
		return nil, nil, errors.New("sm2: key exchange failed, V is infinity point")
	}

	if !ke.genSignature {
		return ke.secret, nil, nil
	}

	return ke.secret, ke.sign(true, 0x02), nil
}

// RepondKeyExchange is for responder's step B1-B8, returns generated Ephemeral Public Key and optional signature
// depends on KeyExchange.genSignature value.
//
// It will check if there are peer's public key and validate the peer's Ephemeral Public Key.
func (ke *KeyExchange) RepondKeyExchange(rand io.Reader, rA *ecdsa.PublicKey) (*ecdsa.PublicKey, []byte, error) {
	r, err := randFieldElement(ke.privateKey, rand)
	if err != nil {
		return nil, nil, err
	}
	return respondKeyExchange(ke, rA, r)
}

// ConfirmResponder for initiator's step A4-A10, returns keying data and optional signature.
//
// It will check if there are peer's public key and validate the peer's Ephemeral Public Key.
//
// If the peer's signature is not empty, then it will also validate the peer's
// signature and return generated signature depends on KeyExchange.genSignature value.
func (ke *KeyExchange) ConfirmResponder(rB *ecdsa.PublicKey, sB []byte) ([]byte, []byte, error) {
	if ke.peerPub == nil {
		return nil, nil, errors.New("sm2: no peer public key given")
	}
	if !ke.privateKey.IsOnCurve(rB.X, rB.Y) {
		return nil, nil, errors.New("sm2: invalid responder's ephemeral public key")
	}
	ke.peerSecret = rB

	ke.mqv()
	if ke.v.X.Sign() == 0 && ke.v.Y.Sign() == 0 {
		return nil, nil, errors.New("sm2: key exchange failed, U is infinity point")
	}

	if len(sB) > 0 {
		buffer := ke.sign(false, 0x02)
		if subtle.ConstantTimeCompare(buffer, sB) != 1 {
			return nil, nil, errors.New("sm2: invalid responder's signature")
		}
	}
	key, err := ke.generateSharedKey(false)
	if err != nil {
		return nil, nil, err
	}

	if !ke.genSignature {
		return key, nil, nil
	}
	return key, ke.sign(false, 0x03), nil
}

// ConfirmInitiator for responder's step B10
func (ke *KeyExchange) ConfirmInitiator(s1 []byte) ([]byte, error) {
	if s1 != nil {
		buffer := ke.sign(true, 0x03)
		if subtle.ConstantTimeCompare(buffer, s1) != 1 {
			return nil, errors.New("sm2: invalid initiator's signature")
		}
	}
	return ke.generateSharedKey(true)
}

var (
	oidSM4    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104}
	oidSM4ECB = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 1}
)

// MarshalEnvelopedPrivateKey, returns sm2 key pair protected data with ASN.1 format:
//
//	SM2EnvelopedKey ::= SEQUENCE {
//	  symAlgID                AlgorithmIdentifier,
//	  symEncryptedKey         SM2Cipher,
//	  sm2PublicKey            SM2PublicKey,
//	  sm2EncryptedPrivateKey  BIT STRING,
//	}
//
// This implementation follows GB/T 35276-2017, uses SM4 cipher to encrypt sm2 private key.
// Please note the standard did NOT clarify if the ECB mode requires padding or not.
//
// This function can be used in CSRResponse.encryptedPrivateKey, reference GM/T 0092-2020
// Specification of certificate request syntax based on SM2 cryptographic algorithm.
func MarshalEnvelopedPrivateKey(rand io.Reader, pub *ecdsa.PublicKey, tobeEnveloped *PrivateKey) ([]byte, error) {
	// encrypt sm2 private key
	size := (tobeEnveloped.Curve.Params().N.BitLen() + 7) / 8
	if tobeEnveloped.D.BitLen() > size*8 {
		return nil, errors.New("sm2: invalid private key")
	}
	plaintext := tobeEnveloped.D.FillBytes(make([]byte, size))

	key := make([]byte, SM4_BlockSize)
	if _, err := io.ReadFull(rand, key); err != nil {
		return nil, err
	}
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := NewECBEncrypter(block)

	encryptedPrivateKey := make([]byte, len(plaintext))
	mode.CryptBlocks(encryptedPrivateKey, plaintext)

	// encrypt the symmetric key
	encryptedKey, err := EncryptASN1(rand, pub, key)
	if err != nil {
		return nil, err
	}

	symAlgID := pkix.AlgorithmIdentifier{
		Algorithm:  oidSM4ECB,
		Parameters: asn1.NullRawValue,
	}
	symAlgIDBytes, _ := asn1.Marshal(symAlgID)

	// marshal the result
	var b Builder
	b.AddASN1(SEQUENCE, func(b *Builder) {
		b.AddBytes(symAlgIDBytes)
		b.AddBytes(encryptedKey)
		b.AddASN1BitString(elliptic.Marshal(tobeEnveloped.Curve, tobeEnveloped.X, tobeEnveloped.Y))
		b.AddASN1BitString(encryptedPrivateKey)
	})
	return b.Bytes()
}

// ParseEnvelopedPrivateKey, parses and decrypts the enveloped SM2 private key.
// This methed just supports SM4 cipher now.
func ParseEnvelopedPrivateKey(priv *PrivateKey, enveloped []byte) (*PrivateKey, error) {
	// unmarshal the asn.1 data
	var (
		symAlgId                              pkix.AlgorithmIdentifier
		encryptedPrivateKey, pub              asn1.BitString
		inner, symEncryptedKey, symAlgIdBytes String
	)
	input := String(enveloped)
	if !input.ReadASN1(&inner, SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Element(&symAlgIdBytes, SEQUENCE) ||
		!inner.ReadASN1Element(&symEncryptedKey, SEQUENCE) ||
		!inner.ReadASN1BitString(&pub) ||
		!inner.ReadASN1BitString(&encryptedPrivateKey) ||
		!inner.Empty() {
		return nil, errors.New("sm2: invalid asn1 format enveloped key")
	}

	if _, err := asn1.Unmarshal(symAlgIdBytes, &symAlgId); err != nil {
		return nil, err
	}

	if !(symAlgId.Algorithm.Equal(oidSM4) || symAlgId.Algorithm.Equal(oidSM4ECB)) {
		return nil, fmt.Errorf("sm2: unsupported symmetric cipher <%v>", symAlgId.Algorithm)
	}

	// parse public key
	pubKey, err := NewPublicKey(pub.RightAlign())
	if err != nil {
		return nil, err
	}

	// decrypt symmetric cipher key
	key, err := priv.Decrypt(rand.Reader, symEncryptedKey, nil)
	if err != nil {
		return nil, err
	}

	// decrypt sm2 private key
	block, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := NewECBDecrypter(block)
	bytes := encryptedPrivateKey.RightAlign()
	plaintext := make([]byte, len(bytes))
	mode.CryptBlocks(plaintext, bytes)
	// Do we need to check length in order to be compatible with some implementations with padding?
	sm2Key, err := NewPrivateKey(plaintext)
	if err != nil {
		return nil, err
	}
	if !sm2Key.PublicKey.Equal(pubKey) {
		return nil, errors.New("sm2: mismatch key pair in enveloped data")
	}

	return sm2Key, nil
}

// sm2ec.go

type sm2ecCurve struct {
	newPoint func() *SM2P256Point
	params   *elliptic.CurveParams
}

var sm2ecp256 = &sm2ecCurve{newPoint: NewSM2P256Point}

func initSM2P256() {
	sm2ecp256.params = sm2ecParams
}

func (curve *sm2ecCurve) Params() *elliptic.CurveParams {
	return curve.params
}

func (curve *sm2ecCurve) IsOnCurve(x, y *big.Int) bool {
	// IsOnCurve is documented to reject (0, 0), the conventional point at
	// infinity, which however is accepted by pointFromAffine.
	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	_, err := curve.pointFromAffine(x, y)
	return err == nil
}

func (curve *sm2ecCurve) pointFromAffine(x, y *big.Int) (p *SM2P256Point, err error) {
	// (0, 0) is by convention the point at infinity, which can't be represented
	// in affine coordinates. See Issue 37294.
	if x.Sign() == 0 && y.Sign() == 0 {
		return curve.newPoint(), nil
	}
	// Reject values that would not get correctly encoded.
	if x.Sign() < 0 || y.Sign() < 0 {
		return p, errors.New("negative coordinate")
	}
	if x.BitLen() > curve.params.BitSize || y.BitLen() > curve.params.BitSize {
		return p, errors.New("overflowing coordinate")
	}
	// Encode the coordinates and let SetBytes reject invalid points.
	byteLen := (curve.params.BitSize + 7) / 8
	buf := make([]byte, 1+2*byteLen)
	buf[0] = 4 // uncompressed point
	x.FillBytes(buf[1 : 1+byteLen])
	y.FillBytes(buf[1+byteLen : 1+2*byteLen])
	return curve.newPoint().SetBytes(buf)
}

func (curve *sm2ecCurve) pointToAffine(p *SM2P256Point) (x, y *big.Int) {
	out := p.Bytes()
	if len(out) == 1 && out[0] == 0 {
		// This is the encoding of the point at infinity, which the affine
		// coordinates API represents as (0, 0) by convention.
		return new(big.Int), new(big.Int)
	}
	byteLen := (curve.params.BitSize + 7) / 8
	x = new(big.Int).SetBytes(out[1 : 1+byteLen])
	y = new(big.Int).SetBytes(out[1+byteLen:])
	return x, y
}

func (curve *sm2ecCurve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	p1, err := curve.pointFromAffine(x1, y1)
	if err != nil {
		panic("sm2/elliptic: Add was called on an invalid point")
	}
	p2, err := curve.pointFromAffine(x2, y2)
	if err != nil {
		panic("sm2/elliptic: Add was called on an invalid point")
	}
	return curve.pointToAffine(p1.Add(p1, p2))
}

func (curve *sm2ecCurve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	p, err := curve.pointFromAffine(x1, y1)
	if err != nil {
		panic("sm2/elliptic: Double was called on an invalid point")
	}
	return curve.pointToAffine(p.Double(p))
}

// normalizeScalar brings the scalar within the byte size of the order of the
// curve, as expected by the nistec scalar multiplication functions.
func (curve *sm2ecCurve) normalizeScalar(scalar []byte) []byte {
	byteSize := (curve.params.N.BitLen() + 7) / 8
	if len(scalar) == byteSize {
		return scalar
	}
	s := new(big.Int).SetBytes(scalar)
	if len(scalar) > byteSize {
		s.Mod(s, curve.params.N)
	}
	out := make([]byte, byteSize)
	return s.FillBytes(out)
}

func (curve *sm2ecCurve) ScalarMult(Bx, By *big.Int, scalar []byte) (*big.Int, *big.Int) {
	p, err := curve.pointFromAffine(Bx, By)
	if err != nil {
		panic("sm2/elliptic: ScalarMult was called on an invalid point")
	}
	scalar = curve.normalizeScalar(scalar)
	p, err = p.ScalarMult(p, scalar)
	if err != nil {
		panic("sm2/elliptic: sm2 rejected normalized scalar")
	}
	return curve.pointToAffine(p)
}

func (curve *sm2ecCurve) ScalarBaseMult(scalar []byte) (*big.Int, *big.Int) {
	scalar = curve.normalizeScalar(scalar)
	p, err := curve.newPoint().ScalarBaseMult(scalar)
	if err != nil {
		panic("sm2/elliptic: sm2 rejected normalized scalar")
	}
	return curve.pointToAffine(p)
}

// CombinedMult returns [s1]G + [s2]P where G is the generator. It's used
// through an interface upgrade in crypto/ecdsa.
func (curve *sm2ecCurve) CombinedMult(Px, Py *big.Int, s1, s2 []byte) (x, y *big.Int) {
	s1 = curve.normalizeScalar(s1)
	q, err := curve.newPoint().ScalarBaseMult(s1)
	if err != nil {
		panic("sm2/elliptic: sm2 rejected normalized scalar")
	}
	p, err := curve.pointFromAffine(Px, Py)
	if err != nil {
		panic("sm2/elliptic: CombinedMult was called on an invalid point")
	}
	s2 = curve.normalizeScalar(s2)
	p, err = p.ScalarMult(p, s2)
	if err != nil {
		panic("sm2/elliptic: sm2 rejected normalized scalar")
	}
	return curve.pointToAffine(p.Add(p, q))
}

func (curve *sm2ecCurve) Unmarshal(data []byte) (x, y *big.Int) {
	if len(data) == 0 || data[0] != 4 {
		return nil, nil
	}
	// Use SetBytes to check that data encodes a valid point.
	_, err := curve.newPoint().SetBytes(data)
	if err != nil {
		return nil, nil
	}
	// We don't use pointToAffine because it involves an expensive field
	// inversion to convert from Jacobian to affine coordinates, which we
	// already have.
	byteLen := (curve.params.BitSize + 7) / 8
	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	y = new(big.Int).SetBytes(data[1+byteLen:])
	return x, y
}

func (curve *sm2ecCurve) UnmarshalCompressed(data []byte) (x, y *big.Int) {
	if len(data) == 0 || (data[0] != 2 && data[0] != 3) {
		return nil, nil
	}
	p, err := curve.newPoint().SetBytes(data)
	if err != nil {
		return nil, nil
	}
	return curve.pointToAffine(p)
}

// Inverse, implements invertible interface, used by Sign()
func (curve *sm2ecCurve) Inverse(k *big.Int) *big.Int {
	if k.Sign() < 0 {
		// This should never happen.
		k = new(big.Int).Neg(k)
	}
	if k.Cmp(curve.params.N) >= 0 {
		// This should never happen.
		k = new(big.Int).Mod(k, curve.params.N)
	}
	scalar := k.FillBytes(make([]byte, 32))
	inverse, err := P256OrdInverse(scalar)
	if err != nil {
		panic("sm2/elliptic: sm2 rejected normalized scalar")
	}
	return new(big.Int).SetBytes(inverse)
}

var initonce sync.Once

var sm2ecParams = &elliptic.CurveParams{
	Name:    "sm2p256v1",
	BitSize: 256,
	P:       bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"),
	N:       bigFromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"),
	B:       bigFromHex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"),
	Gx:      bigFromHex("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"),
	Gy:      bigFromHex("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"),
}

func bigFromHex(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("sm2/elliptic: internal error: invalid encoding")
	}
	return b
}

func initAll() {
	initSM2P256()
}

func sm2ecP256() elliptic.Curve {
	initonce.Do(initAll)
	return sm2ecp256
}

// Since golang 1.19
// unmarshaler is implemented by curves with their own constant-time Unmarshal.
// There isn't an equivalent interface for Marshal/MarshalCompressed because
// that doesn't involve any mathematical operations, only FillBytes and Bit.
type unmarshaler interface {
	Unmarshal([]byte) (x, y *big.Int)
	UnmarshalCompressed([]byte) (x, y *big.Int)
}

func Unmarshal(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	if c, ok := curve.(unmarshaler); ok {
		return c.Unmarshal(data)
	}
	return elliptic.Unmarshal(curve, data)
}

// UnmarshalCompressed converts a point, serialized by MarshalCompressed, into
// an x, y pair. It is an error if the point is not in compressed form, is not
// on the curve, or is the point at infinity. On error, x = nil.
func UnmarshalCompressed(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	if c, ok := curve.(unmarshaler); ok {
		return c.UnmarshalCompressed(data)
	}
	return elliptic.UnmarshalCompressed(curve, data)
}

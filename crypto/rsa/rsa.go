package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// Encrypt RSA
//
// default Padding Pkcs1
// support none padding (unsafe)
func Encrypt(pub *rsa.PublicKey, msg []byte, opts ...Option) ([]byte, error) {
	var c = New(pub, nil, opts...).Encrypt(msg)
	return c.dst, c.Error
}

// Decrypt RSA
//
// default Padding Pkcs1
// support none padding (unsafe)
func Decrypt(priv *rsa.PrivateKey, msg []byte, opts ...Option) ([]byte, error) {
	var c = New(nil, priv, opts...).Decrypt(msg)
	return c.dst, c.Error
}

type Padding uint8

const (
	Pkcs1 Padding = iota
	OEAP
	None
)

type Option func(*option)

type option struct {
	padding Padding
	hash    crypto.Hash
}

func WithPadding(padding Padding) Option {
	return func(o *option) {
		o.padding = padding
	}
}

func WithHash(hash crypto.Hash) Option {
	return func(o *option) {
		o.hash = hash
	}
}

type Cipher struct {
	pub    *rsa.PublicKey
	priv   *rsa.PrivateKey
	option *option
	dst    []byte
	Error  error
}

func text2RsaKey(header, key string) string {
	var s strings.Builder
	s.WriteString(fmt.Sprintf("-----BEGIN %s KEY-----\n", header))

	l := len(key)
	for i := 0; i < l; i += 64 {
		max := i + 64
		if max > l {
			max = l
		}
		s.WriteString(key[i:max] + "\n")
	}

	s.WriteString("-----END " + header + " KEY-----")
	return s.String()
}

// Publickey parse the public key from a string
//
// a string without the word BEGIN END
//
// a string with the word BEGIN END
func Publickey(key string) (pub *rsa.PublicKey) {
	if !strings.Contains(key, "BEGIN") || !strings.Contains(key, "END") {
		key = text2RsaKey("PUBLIC", key)
	}
	var keyText = []byte(key)
	block, _ := pem.Decode(keyText)
	if block == nil {
		return
	}

	parseKey, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		return
	}

	return parseKey.(*rsa.PublicKey)
}

// PrivateKey parse a private key from a string
//
// a string without the word BEGIN END
//
// a string with the word BEGIN END
func PrivateKey(key string) (priv *rsa.PrivateKey) {
	if !strings.Contains(key, "BEGIN") || !strings.Contains(key, "END") {
		key = text2RsaKey("PRIVATE", key)
	}
	var keyText = []byte(key)

	block, _ := pem.Decode(keyText)
	if block == nil {
		return
	}

	parseKey, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return
	}

	return parseKey.(*rsa.PrivateKey)
}

// New RSA
//
//	New().String(gcrypto.Base64) => base64 string
//	New().Encrypt().String(gcrypto.Raw) => utf8 string
//	New().Decrypt().Bytes() => []byte
//	New().Release() => free Cipher to global rsapool
//
// support none padding (unsafe)
func New(pub *rsa.PublicKey, priv *rsa.PrivateKey, opts ...Option) *Cipher {
	var c Cipher
	c.pub = pub
	c.priv = priv
	c.option = &option{}
	for i := range opts {
		opts[i](c.option)
	}
	return &c
}

func (s *Cipher) Bytes() []byte {
	return s.dst
}

func (s *Cipher) String(enc func([]byte) string) (ss string) {
	return enc(s.dst)
}

func (s *Cipher) Encrypt(msg []byte) *Cipher {
	switch s.option.padding {
	case Pkcs1:
		s.dst, s.Error = rsa.EncryptPKCS1v15(rand.Reader, s.pub, msg)
	case None:
		m := new(big.Int).SetBytes(msg)
		e := big.NewInt(int64(s.pub.E))
		s.dst = new(big.Int).Exp(m, e, s.pub.N).Bytes()
	}
	return s
}

func (s *Cipher) Decrypt(msg []byte) *Cipher {
	switch s.option.padding {
	case Pkcs1:
		s.dst, s.Error = rsa.DecryptPKCS1v15(rand.Reader, s.priv, msg)
	case None:
		c := new(big.Int).SetBytes(msg)
		s.dst = new(big.Int).Exp(c, s.priv.D, s.priv.N).Bytes()
	}
	return s
}

func (s *Cipher) EncryptPrivate(msg []byte) *Cipher {
	s.dst, s.Error = s.priKeyEncrypt(rand.Reader, s.priv, msg)
	return s
}

func (s *Cipher) DecryptPublic(msg []byte) *Cipher {
	s.dst, s.Error = s.pubKeyDecrypt(s.pub, msg)
	return s
}

func (s *Cipher) Sign(msg []byte) (buf []byte, e error) {
	return rsa.SignPKCS1v15(rand.Reader, s.priv, s.option.hash, s.hash(msg))
}

func (s *Cipher) Verify(signed, msg []byte) (e error) {
	return rsa.VerifyPKCS1v15(s.pub, s.option.hash, s.hash(msg), signed)
}

func (s *Cipher) hash(src []byte) (dst []byte) {
	var hash = s.option.hash.New()
	hash.Write(src)
	return hash.Sum(nil)
}

func (s *Cipher) pubKeyDecrypt(pub *rsa.PublicKey, data []byte) ([]byte, error) {
	k := (pub.N.BitLen() + 7) / 8
	if k != len(data) {
		return nil, errors.New("data length error")
	}
	m := new(big.Int).SetBytes(data)
	if m.Cmp(pub.N) > 0 {
		return nil, errors.New("message too long for RSA public key size")
	}
	m.Exp(m, big.NewInt(int64(pub.E)), pub.N)
	d := s.leftPad(m.Bytes(), k)
	if d[0] != 0 {
		return nil, errors.New("data broken, first byte is not zero")
	}
	if d[1] != 0 && d[1] != 1 {
		return nil, errors.New("data is not encrypted by the private key")
	}
	var i = 2
	for ; i < len(d); i++ {
		if d[i] == 0 {
			break
		}
	}
	i++
	if i == len(d) {
		return nil, nil
	}
	return d[i:], nil
}

func (s *Cipher) priKeyEncrypt(rand io.Reader, priv *rsa.PrivateKey, hashed []byte) ([]byte, error) {
	tLen := len(hashed)
	k := (priv.N.BitLen() + 7) / 8
	if k < tLen+11 {
		return nil, errors.New("data length error")
	}
	em := make([]byte, k)
	em[1] = 1
	for i := 2; i < k-tLen-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-tLen:k], hashed)
	m := new(big.Int).SetBytes(em)
	c, err := s.decrypt(rand, priv, m)
	if err != nil {
		return nil, err
	}
	s.copyWithLeftPad(em, c.Bytes())
	return em, nil
}

// =========
// copy with std/crypto/rsa
// =========

var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)

func (s *Cipher) decrypt(random io.Reader, priv *rsa.PrivateKey, c *big.Int) (m *big.Int, err error) {
	if c.Cmp(priv.N) > 0 {
		err = rsa.ErrDecryption
		return
	}
	var ir *big.Int
	if random != nil {
		var r *big.Int

		for {
			r, err = rand.Int(random, priv.N)
			if err != nil {
				return
			}
			if r.Cmp(bigZero) == 0 {
				r = bigOne
			}
			var ok bool
			ir, ok = s.modInverse(r, priv.N)
			if ok {
				break
			}
		}
		bigE := big.NewInt(int64(priv.E))
		rpowe := new(big.Int).Exp(r, bigE, priv.N)
		cCopy := new(big.Int).Set(c)
		cCopy.Mul(cCopy, rpowe)
		cCopy.Mod(cCopy, priv.N)
		c = cCopy
	}
	if priv.Precomputed.Dp == nil {
		m = new(big.Int).Exp(c, priv.D, priv.N)
	} else {
		m = new(big.Int).Exp(c, priv.Precomputed.Dp, priv.Primes[0])
		m2 := new(big.Int).Exp(c, priv.Precomputed.Dq, priv.Primes[1])
		m.Sub(m, m2)
		if m.Sign() < 0 {
			m.Add(m, priv.Primes[0])
		}
		m.Mul(m, priv.Precomputed.Qinv)
		m.Mod(m, priv.Primes[0])
		m.Mul(m, priv.Primes[1])
		m.Add(m, m2)

		for i, values := range priv.Precomputed.CRTValues {
			prime := priv.Primes[2+i]
			m2.Exp(c, values.Exp, prime)
			m2.Sub(m2, m)
			m2.Mul(m2, values.Coeff)
			m2.Mod(m2, prime)
			if m2.Sign() < 0 {
				m2.Add(m2, prime)
			}
			m2.Mul(m2, values.R)
			m.Add(m, m2)
		}
	}
	if ir != nil {
		m.Mul(m, ir)
		m.Mod(m, priv.N)
	}

	return
}

func (s *Cipher) copyWithLeftPad(dest, src []byte) {
	numPaddingBytes := len(dest) - len(src)
	for i := 0; i < numPaddingBytes; i++ {
		dest[i] = 0
	}
	copy(dest[numPaddingBytes:], src)
}

func (s *Cipher) leftPad(input []byte, size int) (out []byte) {
	n := len(input)
	if n > size {
		n = size
	}
	out = make([]byte, size)
	copy(out[len(out)-n:], input)
	return
}

func (s *Cipher) modInverse(a, n *big.Int) (ia *big.Int, ok bool) {
	g := new(big.Int)
	x := new(big.Int)
	y := new(big.Int)
	g.GCD(x, y, a, n)
	if g.Cmp(bigOne) != 0 {
		return
	}
	if x.Cmp(bigOne) < 0 {
		x.Add(x, n)
	}
	return x, true
}

package gmsm

import (
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
)

func Sm3(buf []byte) (data []byte) {
	sum := SM3_Sum(buf)
	data = make([]byte, len(sum))
	for k, v := range sum {
		data[k] = v
	}
	return
}

type sm4 struct {
	key     []byte
	iv      []byte
	mode    sm4_mode
	padding sm4_pkcs
}

type sm4_mode int
type sm4_pkcs int

const (
	SM4_Mode_CBC sm4_mode = iota
	SM4_Mode_GCM
	SM4_Mode_CCM
	SM4_Mode_CFB
	SM4_Mode_CTR
	SM4_Mode_OFB
	SM4_Mode_ECB
)

const (
	SM4_Padding_PKCS7 sm4_pkcs = iota
	SM4_Padding_ANSIX923
	SM4_Padding_ISO9797M2
)

type Sm4Option func(*sm4)

func WithSM4Mode(mode sm4_mode) Sm4Option {
	return func(s *sm4) {
		s.mode = mode
	}
}

func WithSM4IV(iv []byte) Sm4Option {
	return func(s *sm4) {
		s.iv = iv
	}
}

func WithSM4Padding(padding sm4_pkcs) Sm4Option {
	return func(s *sm4) {
		s.padding = padding
	}
}

func NewSM4(key []byte, opts ...Sm4Option) *sm4 {
	var s = &sm4{key: key}
	for _, v := range opts {
		v(s)
	}
	return s
}

func (s *sm4) Encrypt(buf []byte) (dst []byte, e error) {
	block, e := NewCipher(s.key)
	if e != nil {
		return
	}

	switch s.mode {
	case SM4_Mode_GCM:
		if len(s.iv) != 12 {
			e = errors.New("iv length must be 12 bytes")
			return
		}
		gcm, e := cipher.NewGCM(block)
		if e != nil {
			return nil, e
		}
		dst = gcm.Seal(nil, s.iv, buf, nil)
	case SM4_Mode_CCM:
		if len(s.iv) != 12 {
			e = errors.New("iv length must be 12 bytes")
			return
		}
		sm4ccm, e := NewCCM(block)
		if e != nil {
			return nil, e
		}
		dst = sm4ccm.Seal(nil, s.iv, buf, nil)
	case SM4_Mode_CFB:
		if len(s.iv) != SM4_BlockSize {
			e = errors.New("iv length must be 16 bytes")
			return
		}
		dst = make([]byte, len(buf))
		mode := cipher.NewCFBEncrypter(block, s.iv)
		mode.XORKeyStream(dst, buf)
	case SM4_Mode_OFB:
		if len(s.iv) != SM4_BlockSize {
			e = errors.New("iv length must be 16 bytes")
			return
		}
		dst = make([]byte, len(buf))
		mode := cipher.NewOFB(block, s.iv)
		mode.XORKeyStream(dst, buf)
	case SM4_Mode_CTR:
		if len(s.iv) != SM4_BlockSize {
			e = errors.New("iv length must be 16 bytes")
			return
		}
		dst = make([]byte, len(buf))
		mode := cipher.NewCTR(block, s.iv)
		mode.XORKeyStream(dst, buf)
	case SM4_Mode_ECB:
		var padding Padding
		switch s.padding {
		case SM4_Padding_ANSIX923:
			padding = NewANSIX923Padding(SM4_BlockSize)
		case SM4_Padding_ISO9797M2:
			padding = NewISO9797M2Padding(SM4_BlockSize)
		default:
			padding = NewPKCS7Padding(SM4_BlockSize)
		}
		buf := padding.Pad(buf)
		dst = make([]byte, len(buf))
		mode := NewECBEncrypter(block)
		mode.CryptBlocks(dst, buf)
	default:
		var padding Padding
		switch s.padding {
		case SM4_Padding_ANSIX923:
			padding = NewANSIX923Padding(SM4_BlockSize)
		case SM4_Padding_ISO9797M2:
			padding = NewISO9797M2Padding(SM4_BlockSize)
		default:
			padding = NewPKCS7Padding(SM4_BlockSize)
		}
		buf := padding.Pad(buf)
		if len(s.iv) != SM4_BlockSize {
			e = errors.New("iv length must be 16 bytes")
			return
		}
		dst = make([]byte, len(buf))
		mode := cipher.NewCBCEncrypter(block, s.iv)
		mode.CryptBlocks(dst, buf)
	}
	return
}

func (s *sm4) Decrypt(buf []byte) (dst []byte, e error) {
	block, e := NewCipher(s.key)
	if e != nil {
		return
	}

	if len(buf) < SM4_BlockSize {
		e = errors.New("ciphertext too short")
		return
	}

	switch s.mode {
	case SM4_Mode_GCM:
		if len(s.iv) != 12 {
			e = errors.New("iv length must be 12 bytes")
			return
		}
		gcm, e := cipher.NewGCM(block)
		if e != nil {
			return nil, e
		}
		dst, e = gcm.Open(nil, s.iv, buf, nil)
	case SM4_Mode_CCM:
		if len(s.iv) != 12 {
			e = errors.New("iv length must be 12 bytes")
			return
		}
		sm4ccm, e := NewCCM(block)
		if e != nil {
			return nil, e
		}
		dst, e = sm4ccm.Open(nil, s.iv, buf, nil)
	case SM4_Mode_CFB:
		if len(s.iv) != SM4_BlockSize {
			e = errors.New("iv length must be 16 bytes")
			return
		}
		dst = make([]byte, len(buf))
		mode := cipher.NewCFBDecrypter(block, s.iv)
		mode.XORKeyStream(dst, buf)
	case SM4_Mode_OFB:
		if len(s.iv) != SM4_BlockSize {
			e = errors.New("iv length must be 16 bytes")
			return
		}
		dst = make([]byte, len(buf))
		mode := cipher.NewOFB(block, s.iv)
		mode.XORKeyStream(dst, buf)
	case SM4_Mode_CTR:
		if len(s.iv) != SM4_BlockSize {
			e = errors.New("iv length must be 16 bytes")
			return
		}
		dst = make([]byte, len(buf))
		mode := cipher.NewCTR(block, s.iv)
		mode.XORKeyStream(dst, buf)
	case SM4_Mode_ECB:
		dst = make([]byte, len(buf))
		mode := NewECBDecrypter(block)
		mode.CryptBlocks(dst, buf)
		var padding Padding
		switch s.padding {
		case SM4_Padding_ANSIX923:
			padding = NewANSIX923Padding(SM4_BlockSize)
		case SM4_Padding_ISO9797M2:
			padding = NewISO9797M2Padding(SM4_BlockSize)
		default:
			padding = NewPKCS7Padding(SM4_BlockSize)
		}
		dst, e = padding.Unpad(dst)
	default:
		if len(s.iv) != SM4_BlockSize {
			e = errors.New("iv length must be 16 bytes")
			return
		}
		dst = make([]byte, len(buf))
		mode := cipher.NewCBCDecrypter(block, s.iv)
		mode.CryptBlocks(dst, buf)

		var padding Padding
		switch s.padding {
		case SM4_Padding_ANSIX923:
			padding = NewANSIX923Padding(SM4_BlockSize)
		case SM4_Padding_ISO9797M2:
			padding = NewISO9797M2Padding(SM4_BlockSize)
		default:
			padding = NewPKCS7Padding(SM4_BlockSize)
		}
		dst, e = padding.Unpad(dst)
	}

	return
}

type sm2 struct {
	priv *PrivateKey
	opts *EncrypterOpts
}

type Sm2Option func(*sm2)

func WithSM2Mode(mode pointMarshalMode) Sm2Option {
	return func(s *sm2) {
		s.opts.pointMarshalMode = mode
	}
}

func WithSM2Order(order ciphertextSplicingOrder) Sm2Option {
	return func(s *sm2) {
		s.opts.ciphertextSplicingOrder = order
	}
}

func WithSM2Encoding(enc ciphertextEncoding) Sm2Option {
	return func(s *sm2) {
		s.opts.ciphertextEncoding = enc
	}
}

func GenerateSM2Key() (priv []byte, pub []byte, e error) {
	key, e := GenerateKey(rand.Reader)
	if e != nil {
		return
	}
	priv = key.D.Bytes()
	pub = elliptic.Marshal(key.Curve, key.X, key.Y)
	return
}

func NewSM2(priv *PrivateKey, opts ...Sm2Option) *sm2 {
	s := &sm2{priv: priv, opts: defaultEncrypterOpts}
	for _, v := range opts {
		v(s)
	}
	return s
}

func (s *sm2) Encrypt(buf []byte) (dst []byte, e error) {
	dst, e = Encrypt(rand.Reader, &s.priv.PublicKey, buf, s.opts)
	return
}

func (s *sm2) Decrypt(buf []byte) (dst []byte, e error) {
	dst, e = s.priv.Decrypt(nil, buf, s.opts)
	return
}

func (s *sm2) Verify(buf, signed []byte) bool {
	return VerifyASN1WithSM2(&s.priv.PublicKey, nil, buf, signed)
}

func (s *sm2) Signature(buf []byte) ([]byte, error) {
	return s.priv.Sign(rand.Reader, buf, DefaultSM2SignerOpts)
}

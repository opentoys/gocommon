package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

// Encrypt AES
//
// support 128/192/256bit Mapping key length 16byte/24byte/32byte
//
// support ECB/CBC/CTR/OFB/CFB mode
//
// support	Pkcs7/Pkcs5/Iso97971/AnsiX923/Zero/Empty/No padding
//
// without iv default: mode = ECB/Pkcs7padding
//
// withiv default: mode = CBC/Pkcs7padding
func Encrypt(msg, key []byte, opts ...Option) ([]byte, error) {
	var c = New(key, opts...).Encrypt(msg)
	return c.dst, c.Error
}

// Decrypt AES
//
// support 128/192/256bit Mapping key length 16byte/24byte/32byte
//
// support ECB/CBC/CTR/OFB/CFB mode
//
// support	Pkcs7/Pkcs5/Iso97971/AnsiX923/Zero/Empty/No padding
//
// without iv default: mode = ECB/Pkcs7padding
//
// withiv default: mode = CBC/Pkcs7padding
func Decrypt(msg, key []byte, opts ...Option) ([]byte, error) {
	var c = New(key, opts...).Decrypt(msg)
	return c.dst, c.Error
}

// ========
//
// ========

type Mode uint8
type Padding uint8

const (
	CBC Mode = iota
	CFB
	CTR
	OFB
	ECB
)

const (
	Pkcs7 Padding = iota
	Pkcs5
	Iso97971
	AnsiX923
	Zero
	Empty
	No
)

type Option func(*Cipher)

func WithIV(iv []byte) Option {
	return func(o *Cipher) {
		o.iv = iv
	}
}

func WithMode(mode Mode) Option {
	return func(o *Cipher) {
		o.mode = mode
	}
}

func WithPadding(padding Padding) Option {
	return func(o *Cipher) {
		o.padding = padding
	}
}

// 用于加密时返回密文编码格式
// Used to return ciphertext encoding format when encrypting
func WithEncode(enc func([]byte) string) Option {
	return func(o *Cipher) {
		o.encode = enc
	}
}

// 用于解密时解密字符串类型解码
// Used for decryption string type decoding when decrypting
func WithDecode(dec func(string) ([]byte, error)) Option {
	return func(o *Cipher) {
		o.decode = dec
	}
}

type Cipher struct {
	key   []byte
	dst   []byte
	Error error

	iv      []byte
	mode    Mode
	padding Padding
	encode  func([]byte) string
	decode  func(string) ([]byte, error)
}

// New AES
//
// support 128/192/256bit Mapping key length 16byte/24byte/32byte
//
// support ECB/CBC/CTR/OFB/CFB mode
//
// support	Pkcs7/Pkcs5/Iso97971/AnsiX923/Zero/Empty/No padding
//
// without iv default: mode = ECB/Pkcs7padding
//
// withiv default: mode = CBC/Pkcs7padding
//
//	New([]byte("1234567890123456")).Encrypt(msg).String(gcrypto.Base64)
//	New([]byte("1234567890123456")).Decrypt(msg).String(gcrypto.Raw)
//	New([]byte("1234567890123456")).Decrypt(msg).Bytes()
//	New([]byte("1234567890123456")).Decrypt(msg).Error
func New(key []byte, opts ...Option) *Cipher {
	var c = &Cipher{
		key:    key,
		encode: base64.StdEncoding.EncodeToString,
		decode: base64.StdEncoding.DecodeString,
	}
	for i := range opts {
		opts[i](c)
	}
	if len(c.iv) == 0 {
		c.mode = ECB
	}
	return c
}

func (s *Cipher) Bytes() []byte {
	return s.dst
}

func (s *Cipher) String() (ss string) {
	return s.encode(s.dst)
}

func (s *Cipher) emptyPadding(src []byte, blockSize int) (buf []byte) {
	paddingSize := blockSize - len(src)%blockSize
	paddingText := bytes.Repeat([]byte(" "), paddingSize)
	return append(src, paddingText...)
}

func (s *Cipher) emptyUnPadding(src []byte, blockSize int) (buf []byte) {
	return bytes.TrimRight(src, " ")
}

func (s *Cipher) zeroPadding(src []byte, blockSize int) (buf []byte) {
	paddingSize := blockSize - len(append(src, 0x80))%blockSize
	paddingText := bytes.Repeat([]byte{byte(0)}, paddingSize)
	return append(src, paddingText...)
}

func (s *Cipher) zeroUnPadding(src []byte, blockSize int) (buf []byte) {
	return bytes.TrimRight(src, string([]byte{0}))
}

func (s *Cipher) ansiX923Padding(src []byte, blockSize int) (buf []byte) {
	paddingSize := blockSize - len(src)%blockSize
	paddingText := append(bytes.Repeat([]byte{byte(0)}, paddingSize-1), byte(paddingSize))
	return append(src, paddingText...)
}

func (s *Cipher) ansiX923UnPadding(src []byte, blockSize int) (buf []byte) {
	if len(src) == 0 {
		return []byte("")
	}
	n := len(src) - int(src[len(src)-1])
	return src[0:n]
}

func (s *Cipher) iso97971Padding(src []byte, blockSize int) (buf []byte) {
	return s.zeroPadding(append(src, 0x80), blockSize)
}

func (s *Cipher) iso97971UnPadding(src []byte, blockSize int) (buf []byte) {
	dst := s.zeroUnPadding(src, blockSize)
	return dst[:len(dst)-1]
}

func (s *Cipher) pkcs7Padding(src []byte, blockSize int) (buf []byte) {
	paddingSize := blockSize - len(src)%blockSize
	paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	return append(src, paddingText...)
}

func (s *Cipher) pkcs7UnPadding(src []byte, blockSize int) (buf []byte) {
	if len(src) == 0 {
		return []byte("")
	}
	n := len(src) - int(src[len(src)-1])
	return src[0:n]
}

func (s *Cipher) pkcs5Padding(src []byte, blockSize int) (buf []byte) {
	return s.pkcs7Padding(src, 16)
}

func (s *Cipher) pkcs5UnPadding(src []byte, blockSize int) (buf []byte) {
	return s.pkcs7UnPadding(src, blockSize)
}

// NewCBCEncrypter encrypts with CBC mode.
func (s *Cipher) newCBCEncrypter(src []byte, block cipher.Block) (dst []byte) {
	dst = make([]byte, len(src))
	cipher.NewCBCEncrypter(block, s.iv).CryptBlocks(dst, src)
	return
}

// NewCBCDecrypter decrypts with CBC mode.
func (s *Cipher) newCBCDecrypter(src []byte, block cipher.Block) (dst []byte) {
	dst = make([]byte, len(src))
	cipher.NewCBCDecrypter(block, s.iv).CryptBlocks(dst, src)
	return
}

// NewCFBEncrypter encrypts with CFB mode.
func (s *Cipher) newCFBEncrypter(src []byte, block cipher.Block) (dst []byte) {
	dst = make([]byte, len(src))
	cipher.NewCFBEncrypter(block, s.iv).XORKeyStream(dst, src)
	return
}

// NewCFBDecrypter decrypts with CFB mode.
func (s *Cipher) newCFBDecrypter(src []byte, block cipher.Block) (dst []byte) {
	dst = make([]byte, len(src))
	cipher.NewCFBDecrypter(block, s.iv).XORKeyStream(dst, src)
	return
}

// NewCTREncrypter encrypts with CTR mode.
func (s *Cipher) newCTREncrypter(src []byte, block cipher.Block) (dst []byte) {
	dst = make([]byte, len(src))
	cipher.NewCTR(block, s.iv).XORKeyStream(dst, src)
	return
}

// NewCTRDecrypter decrypts with CTR mode.
func (s *Cipher) newCTRDecrypter(src []byte, block cipher.Block) (dst []byte) {
	dst = make([]byte, len(src))
	cipher.NewCTR(block, s.iv).XORKeyStream(dst, src)
	return
}

// NewECBEncrypter encrypts with ECB mode.
func (s *Cipher) newECBEncrypter(src []byte, block cipher.Block) (dst []byte) {
	dst = make([]byte, len(src))
	encrypted, blockSize := dst, block.BlockSize()
	for len(src) > 0 {
		block.Encrypt(encrypted, src[:blockSize])
		src = src[blockSize:]
		encrypted = encrypted[blockSize:]
	}
	return
}

// NewECBDecrypter decrypts with ECB mode.
func (s *Cipher) newECBDecrypter(src []byte, block cipher.Block) (dst []byte) {
	dst = make([]byte, len(src))
	decrypted, blockSize := dst, block.BlockSize()
	for len(src) > 0 {
		block.Decrypt(decrypted, src[:blockSize])
		src = src[blockSize:]
		decrypted = decrypted[blockSize:]
	}
	return
}

// NewOFBEncrypter encrypts with OFB mode.
func (s *Cipher) newOFBEncrypter(src []byte, block cipher.Block) (dst []byte) {
	dst = make([]byte, len(src))
	cipher.NewOFB(block, s.iv[:block.BlockSize()]).XORKeyStream(dst, src)
	return
}

// NewOFBDecrypter decrypts with OFB mode.
func (s *Cipher) newOFBDecrypter(src []byte, block cipher.Block) (dst []byte) {
	dst = make([]byte, len(src))
	cipher.NewOFB(block, s.iv[:block.BlockSize()]).XORKeyStream(dst, src)
	return
}

func (s *Cipher) DecryptString(src string) *Cipher {
	buf, e := s.decode(src)
	if e != nil {
		s.Error = e
		return s
	}
	return s.Decrypt(buf)
}

// Encrypt encrypts with given mode and padding
func (s *Cipher) Encrypt(src []byte) *Cipher {
	block, e := aes.NewCipher(s.key)
	if e != nil {
		s.Error = e
		return s
	}

	size := block.BlockSize()
	if len(src) == 0 {
		return s
	}

	switch s.padding {
	case No:
		if len(src)%size != 0 {
			s.Error = errors.New("aes: invalid src, the src is not full blocks")
			return s
		}
	case Empty:
		src = s.emptyPadding(src, size)
	case Pkcs5:
		src = s.pkcs5Padding(src, size)
	case Pkcs7:
		src = s.pkcs7Padding(src, size)
	case AnsiX923:
		src = s.ansiX923Padding(src, size)
	case Iso97971:
		src = s.iso97971Padding(src, size)
	case Zero:
		src = s.zeroPadding(src, size)
	}

	switch s.mode {
	case ECB:
		s.dst = s.newECBEncrypter(src, block)
	case CTR:
		s.dst = s.newCTREncrypter(src, block)
	case CFB:
		s.dst = s.newCFBEncrypter(src, block)
	case OFB:
		s.dst = s.newOFBEncrypter(src, block)
	case CBC:
		s.dst = s.newCBCEncrypter(src, block)
	}
	return s
}

// Decrypt decrypts with given mode and padding.
func (s *Cipher) Decrypt(src []byte) *Cipher {
	block, e := aes.NewCipher(s.key)
	if e != nil {
		s.Error = e
		return s
	}

	size := block.BlockSize()
	if len(src) == 0 {
		return s
	}

	switch s.mode {
	case ECB:
		src = s.newECBDecrypter(src, block)
	case CTR:
		src = s.newCTRDecrypter(src, block)
	case CFB:
		src = s.newCFBDecrypter(src, block)
	case OFB:
		src = s.newOFBDecrypter(src, block)
	case CBC:
		src = s.newCBCDecrypter(src, block)
	}

	switch s.padding {
	case No:
		if len(src)%size != 0 {
			s.Error = errors.New("aes: invalid src, the src is not full blocks")
			return s
		}
	case Zero:
		s.dst = s.zeroUnPadding(src, size)
	case Empty:
		s.dst = s.emptyUnPadding(src, size)
	case Pkcs5:
		s.dst = s.pkcs5UnPadding(src, size)
	case AnsiX923:
		s.dst = s.ansiX923UnPadding(src, size)
	case Iso97971:
		s.dst = s.iso97971UnPadding(src, size)
	case Pkcs7:
		s.dst = s.pkcs7UnPadding(src, size)
	}
	return s
}

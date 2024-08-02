package gmsm

import (
	"crypto/cipher"
)

// ecb.go

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

func validate(size int, dst, src []byte) {
	if len(src)%size != 0 {
		panic("cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("cipher: output smaller than input")
	}
	if InexactOverlap(dst[:len(src)], src) {
		panic("cipher: invalid buffer overlap")
	}
}

type ecbEncrypter ecb

// ecbEncAble is an interface implemented by ciphers that have a specific
// optimized implementation of ECB encryption, like sm4.
// NewECBEncrypter will check for this interface and return the specific
// BlockMode if found.
type ecbEncAble interface {
	NewECBEncrypter() cipher.BlockMode
}

// NewECBEncrypter returns a BlockMode which encrypts in electronic code book
// mode, using the given Block.
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	if ecb, ok := b.(ecbEncAble); ok {
		return ecb.NewECBEncrypter()
	}
	return (*ecbEncrypter)(newECB(b))
}

func (x *ecbEncrypter) BlockSize() int { return x.blockSize }

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	validate(x.blockSize, dst, src)

	for len(src) > 0 {
		x.b.Encrypt(dst[:x.blockSize], src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

type ecbDecrypter ecb

// ecbDecAble is an interface implemented by ciphers that have a specific
// optimized implementation of ECB decryption, like sm4.
// NewECBDecrypter will check for this interface and return the specific
// BlockMode if found.
type ecbDecAble interface {
	NewECBDecrypter() cipher.BlockMode
}

// NewECBDecrypter returns a BlockMode which decrypts in electronic code book
// mode, using the given Block.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	if ecb, ok := b.(ecbDecAble); ok {
		return ecb.NewECBDecrypter()
	}
	return (*ecbDecrypter)(newECB(b))
}

func (x *ecbDecrypter) BlockSize() int { return x.blockSize }

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	validate(x.blockSize, dst, src)

	if len(src) == 0 {
		return
	}

	for len(src) > 0 {
		x.b.Decrypt(dst[:x.blockSize], src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

// bc.go

type bc struct {
	b         cipher.Block
	blockSize int
	iv        []byte
}

func newBC(b cipher.Block, iv []byte) *bc {
	c := &bc{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        make([]byte, b.BlockSize()),
	}
	copy(c.iv, iv)
	return c
}

type bcEncrypter bc

// bcEncAble is an interface implemented by ciphers that have a specific
// optimized implementation of BC encryption.
// NewBCEncrypter will check for this interface and return the specific
// BlockMode if found.
type bcEncAble interface {
	NewBCEncrypter(iv []byte) cipher.BlockMode
}

// NewBCEncrypter returns a BlockMode which encrypts in block chaining
// mode, using the given Block. The length of iv must be the same as the
// Block's block size.
func NewBCEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	if len(iv) != b.BlockSize() {
		panic("cipher.NewBCEncrypter: IV length must equal block size")
	}
	if bc, ok := b.(bcEncAble); ok {
		return bc.NewBCEncrypter(iv)
	}
	return (*bcEncrypter)(newBC(b, iv))
}

func (x *bcEncrypter) BlockSize() int { return x.blockSize }

func (x *bcEncrypter) CryptBlocks(dst, src []byte) {
	validate(x.blockSize, dst, src)

	iv := x.iv

	for len(src) > 0 {
		// Write the xor to dst, then encrypt in place.
		XORBytes(dst[:x.blockSize], src[:x.blockSize], iv)
		x.b.Encrypt(dst[:x.blockSize], dst[:x.blockSize])
		XORBytes(iv, iv, dst[:x.blockSize])

		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}

	// Save the iv for the next CryptBlocks call.
	copy(x.iv, iv)
}

func (x *bcEncrypter) SetIV(iv []byte) {
	if len(iv) != len(x.iv) {
		panic("cipher: incorrect length IV")
	}
	copy(x.iv, iv)
}

type bcDecrypter bc

// bcDecAble is an interface implemented by ciphers that have a specific
// optimized implementation of BC decryption.
// NewBCDecrypter will check for this interface and return the specific
// BlockMode if found.
type bcDecAble interface {
	NewBCDecrypter(iv []byte) cipher.BlockMode
}

// NewBCDecrypter returns a BlockMode which decrypts in block chaining
// mode, using the given Block. The length of iv must be the same as the
// Block's block size and must match the iv used to encrypt the data.
func NewBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	if len(iv) != b.BlockSize() {
		panic("cipher.NewBCDecrypter: IV length must equal block size")
	}
	if bc, ok := b.(bcDecAble); ok {
		return bc.NewBCDecrypter(iv)
	}
	return (*bcDecrypter)(newBC(b, iv))
}

func (x *bcDecrypter) BlockSize() int { return x.blockSize }

func (x *bcDecrypter) CryptBlocks(dst, src []byte) {
	validate(x.blockSize, dst, src)

	if len(src) == 0 {
		return
	}

	iv := x.iv
	nextIV := make([]byte, x.blockSize)

	for len(src) > 0 {
		// Get F(i+1)
		XORBytes(nextIV, iv, src[:x.blockSize])
		// Get plaintext P(i)
		x.b.Decrypt(dst[:x.blockSize], src[:x.blockSize])
		XORBytes(dst[:x.blockSize], dst[:x.blockSize], iv)

		copy(iv, nextIV)
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}

	// Save the iv for the next CryptBlocks call.
	copy(x.iv, iv)
}

func (x *bcDecrypter) SetIV(iv []byte) {
	if len(iv) != len(x.iv) {
		panic("cipher: incorrect length IV")
	}
	copy(x.iv, iv)
}

package aes_test

import (
	"math/big"
	"testing"

	"github.com/opentoys/gocommon/crypto/aes"
)

func TestAES_ECB_WithoutPool(t *testing.T) {
	var c = aes.New([]byte("1234567890123456")).Encrypt(new(big.Int).SetInt64(int64(124)).Bytes())
	if c.Error != nil {
		t.Fatal(c.Error)
	}
	c = aes.New([]byte("1234567890123456")).Decrypt(c.Bytes())
	if c.Error != nil {
		t.Fatal(c.Error)
	}
}

func BenchmarkAES_ECB_WithoutPool(b *testing.B) {
	for i := 0; i < b.N; i++ {
		var c = aes.New([]byte("1234567890123456")).Encrypt(new(big.Int).SetInt64(int64(i)).Bytes())
		if c.Error != nil {
			b.Fatal(c.Error)
		}
		c = aes.New([]byte("1234567890123456")).Decrypt(c.Bytes())
		if c.Error != nil {
			b.Fatal(c.Error)
		}
	}
}

package aes_test

import (
	"math/big"
	"testing"

	"github.com/opentoys/gocommon/gcrypto/aes"
)

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

func BenchmarkAES_ECB_WithPool(b *testing.B) {
	for i := 0; i < b.N; i++ {
		var c = aes.NewWithPool([]byte("1234567890123456")).Encrypt(new(big.Int).SetInt64(int64(i)).Bytes())
		if c.Error != nil {
			b.Fatal(c.Error)
		}
		c.Release()
		c = aes.NewWithPool([]byte("1234567890123456")).Decrypt(c.Bytes())
		if c.Error != nil {
			b.Fatal(c.Error)
		}
		c.Release()
	}
}

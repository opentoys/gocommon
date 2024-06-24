package aes_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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

func TestAes(t *testing.T) {
	var data = make(map[string]interface{})
	buf, e := json.Marshal(data)
	if e != nil {
		t.Fatal(e)
	}
	buf, e = aes.Encrypt(buf, []byte("1234567890123456"), aes.WithIV([]byte("1234567890123456")))
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(buf))
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

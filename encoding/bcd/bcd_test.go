package bcd

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"
)

func TestBCD(t *testing.T) {
	// NewCodec(Standard).Encoder.Encode()
	buf, e := StdEncoding.Encode([]byte("123"))
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range new(big.Int).SetBytes(buf).Bits() {
		fmt.Printf("%b", v)
	}
	fmt.Println("")
	fmt.Println(buf, base64.StdEncoding.EncodeToString(buf))
	buf, e = StdEncoding.Decode(buf)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println(buf, string(buf))
}

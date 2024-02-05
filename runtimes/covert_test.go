package runtimes

import (
	"fmt"
	"testing"
)

func TestString2Bytes(t *testing.T) {
	buf := String2Bytes("hello")
	// buf[0] = 'a' will panic
	fmt.Println(Bytes2String(buf))
}

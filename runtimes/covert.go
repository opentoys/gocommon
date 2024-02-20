package runtimes

import (
	"encoding/json"
	"unsafe"
)

// String2Bytes will unsafe
func String2Bytes(s string) []byte {
	x := (*[2]uintptr)(unsafe.Pointer(&s))
	h := [3]uintptr{x[0], x[1], x[1]}
	return *(*[]byte)(unsafe.Pointer(&h))
}

// Bytes2String will unsafe
func Bytes2String(buf []byte) string {
	return *(*string)(unsafe.Pointer(&buf))
}

func Strnigify(v interface{}) string {
	s, _ := json.Marshal(v)
	return Bytes2String(s)
}

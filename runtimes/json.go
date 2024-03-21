package runtimes

import "encoding/json"

type _json struct{}

var JSON _json

func (s _json) Stringify(i interface{}) string {
	return Bytes2String(s.Bytes(i))
}

func (s _json) Bytes(i interface{}) []byte {
	v, _ := json.Marshal(i)
	return v
}

func (_json) Copy(dst, src interface{}) (e error) {
	buf, e := json.Marshal(dst)
	if e != nil {
		return
	}
	return json.Unmarshal(buf, src)
}

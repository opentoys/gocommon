package json_test

import (
	"encoding/json"
	"fmt"
	"testing"

	newjson "github.com/opentoys/gocommon/encoding/json"
)

func TestJSON(t *testing.T) {
	var mm, e = newjson.Parse([]byte(`{"a":1,"b":"hello","c":false,"d":{"a":1.234}}`))
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println(mm.Map())

	s, e := newjson.Stringify(mm.Map())
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println(string(s))
}

func BenchmarkStdJSON2Map(b *testing.B) {
	var buf = []byte(`{"a":1,"b":"hello","c":false,"d":{"a":1.234}}`)
	for i := 0; i < b.N; i++ {
		var m = make(map[string]interface{})
		if e := json.Unmarshal(buf, &m); e != nil {
			b.Fatal(e)
		}
	}
}

func BenchmarkNewJSON2Map(b *testing.B) {
	var buf = []byte(`{"a":1,"b":"hello","c":false,"d":{"a":1.234}}`)
	for i := 0; i < b.N; i++ {
		var m = make(map[string]interface{})
		if r, e := newjson.Parse(buf); e != nil {
			b.Fatal(e)
		} else {
			m = r.Map()
		}
		_ = m
	}
}

package webx

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"
)

const (
	headerContentType = "Content-Type"
)

const (
	type_xml        = "xml"
	type_json       = "json"
	type_urlencoded = "urlencoded"
)

func parseMapArray(data map[string][]string, v any, tag string) {
	vv := reflect.Indirect(reflect.ValueOf(v))
	vt := vv.Type()
	if vt.Kind() != reflect.Struct {
		return
	}
	n := vt.NumField()
	for i := 0; i < n; i++ {
		vf := vt.Field(i)
		vvf := vv.Field(i)
		t := vf.Tag.Get(tag)
		var tv string
		if t == "" {
			t = vf.Name
		}
		if t != "" && len(data[t]) > 0 {
			tv = data[t][0]
			switch itemtyp := vf.Type.Kind(); itemtyp {
			case reflect.Bool:
				vvf.SetBool(tv != "" && (tv == "true" || tv == "t" || tv == "1" || tv == "T"))
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				n, _ := strconv.ParseInt(tv, 10, 64)
				vvf.SetInt(n)
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				n, _ := strconv.ParseUint(tv, 10, 64)
				vvf.SetUint(n)
			case reflect.Float32, reflect.Float64:
				n, _ := strconv.ParseFloat(tv, 64)
				vvf.SetFloat(n)
			case reflect.String:
				vvf.SetString(tv)
			}
		}
	}
}

func UnmarshalFormUrlencoded(buf []byte, v any) (e error) {
	vs, e := url.ParseQuery(string(buf))
	if e != nil {
		return e
	}
	e = FormEncoded(vs, v, "form")
	return
}

var FormEncoded = func(data map[string][]string, out any, tag string) (e error) {
	parseMapArray(data, out, tag)
	return
}

var decodes = map[string]func([]byte, any) error{
	type_xml:        xml.Unmarshal,
	type_json:       json.Unmarshal,
	type_urlencoded: UnmarshalFormUrlencoded,
	"":              func(b []byte, a any) (e error) { return },
}

var encodes = map[string]func(any) ([]byte, error){
	type_xml:  xml.Marshal,
	type_json: json.Marshal,
	"":        func(v any) ([]byte, error) { return []byte(fmt.Sprintf("%#v", v)), nil },
}

func RegisterDecode(typ string, fn func([]byte, any) error) {
	decodes[typ] = fn
}

func RegisterEncode(typ string, fn func(any) ([]byte, error)) {
	encodes[typ] = fn
}

func encode(header string) func(v any) ([]byte, error) {
	if strings.Contains(header, type_json) {
		return encodes[type_json]
	}
	if strings.Contains(header, type_xml) {
		return encodes[type_xml]
	}
	return encodes[""]
}

func decode(header string) func([]byte, any) error {
	if strings.Contains(header, type_json) {
		return decodes[type_json]
	}
	if strings.Contains(header, type_xml) {
		return decodes[type_xml]
	}
	if strings.Contains(header, type_urlencoded) {
		return decodes[type_urlencoded]
	}
	return decodes[""]
}

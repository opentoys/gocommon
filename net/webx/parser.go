package webx

import (
	"encoding/json"
	"encoding/xml"
	"net/url"
	"reflect"
	"strconv"
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

var Decode = map[string]func([]byte, any) error{
	"text/xml":                          xml.Unmarshal,
	"application/xml":                   xml.Unmarshal,
	"text/xhtml":                        xml.Unmarshal,
	"application/json":                  json.Unmarshal,
	"application/x-www-form-urlencoded": UnmarshalFormUrlencoded,
	"text/x-www-form-urlencoded":        UnmarshalFormUrlencoded,
}

var Encode = map[string]func(any) ([]byte, error){
	"text/xml":         xml.Marshal,
	"application/xml":  xml.Marshal,
	"text/xhtml":       xml.Marshal,
	"application/json": json.Marshal,
}

var FormEncoded = func(data map[string][]string, out any, tag string) (e error) {
	parseMapArray(data, out, tag)
	return
}

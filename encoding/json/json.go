package json

// fork and modify github.com/mreiferson/go-ujson

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"strconv"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	ErrIndexExceededMaximumLength = errors.New("index exceeded maximum length of j.data")
)

const (
	JT_NULL = iota
	JT_TRUE
	JT_FALSE
	JT_NUMERIC
	JT_UTF8
	JT_ARRAY
	JT_OBJECT
	JT_INVALID
)

type ObjectStore interface {
	NewObject() (interface{}, error)
	NewArray() (interface{}, error)
	ObjectAddKey(interface{}, interface{}, interface{}) error
	ArrayAddItem(interface{}, interface{}) error
	NewString([]byte) (interface{}, error)
	NewNumeric([]byte) (interface{}, error)
	NewTrue() (interface{}, error)
	NewFalse() (interface{}, error)
	NewNull() (interface{}, error)
}

type Decoder struct {
	store      ObjectStore
	data       []byte
	idx        int64
	lastTypeId int
}

func NewDecoder(store ObjectStore, data []byte) *Decoder {
	return &Decoder{
		store: store,
		data:  data,
	}
}

func (j *Decoder) Decode() (interface{}, error) {
	j.idx = 0
	j.lastTypeId = JT_INVALID
	return j.decodeAny()
}

func (j *Decoder) skipWhitespace() {
	maxLength := int64(len(j.data))

	for {
		if j.idx >= maxLength {
			return
		}

		switch j.data[j.idx] {
		case ' ', '\t', '\r', '\n':
			j.idx++
			continue
		}
		break
	}
}

func (j *Decoder) decodeAny() (interface{}, error) {
	for {
		c := j.data[j.idx]
		switch c {
		case '"':
			return j.decodeString()
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-':
			return j.decodeNumeric()
		case '[':
			return j.decodeArray()
		case '{':
			return j.decodeObject()
		case 't':
			return j.decodeTrue()
		case 'f':
			return j.decodeFalse()
		case 'n':
			return j.decodeNull()
		case ' ', '\t', '\r', '\n':
			j.idx++
			continue
		}
		break
	}

	return nil, errors.New("expected object or value")
}

func (j *Decoder) decodeObject() (interface{}, error) {
	newObj, err := j.store.NewObject()
	if err != nil {
		return nil, err
	}

	maxLength := int64(len(j.data))
	j.idx++

	for {
		j.skipWhitespace()

		if j.idx >= maxLength {
			return nil, ErrIndexExceededMaximumLength
		}

		if j.data[j.idx] == '}' {
			j.idx++
			return newObj, nil
		}

		j.lastTypeId = JT_INVALID
		itemName, err := j.decodeAny()
		if err != nil {
			return "", err
		}

		if j.lastTypeId != JT_UTF8 {
			return nil, errors.New("key name of object must be 'string' when decoding 'object'")
		}

		j.skipWhitespace()

		nextChar := j.data[j.idx]
		j.idx++
		if nextChar != ':' {
			return nil, errors.New("no ':' found when decoding object value")
		}

		j.skipWhitespace()

		itemValue, err := j.decodeAny()
		if err != nil {
			return nil, err
		}

		err = j.store.ObjectAddKey(newObj, itemName, itemValue)
		if err != nil {
			return nil, err
		}

		j.skipWhitespace()

		nextChar = j.data[j.idx]
		j.idx++
		switch nextChar {
		case '}':
			return newObj, nil
		case ',':
			continue
		}
		break
	}

	return nil, errors.New("unexpected character in found when decoding object value")
}

func (j *Decoder) decodeArray() (interface{}, error) {
	var length int

	newObj, err := j.store.NewArray()
	if err != nil {
		return nil, err
	}

	j.lastTypeId = JT_INVALID

	maxLength := int64(len(j.data))
	j.idx++

	for {
		j.skipWhitespace()

		if j.idx >= maxLength {
			return nil, ErrIndexExceededMaximumLength
		}

		if j.data[j.idx] == ']' {
			if length == 0 {
				j.idx++
				return newObj, nil
			}
			return nil, fmt.Errorf("unexpected character found when decoding array value (%d)", length)
		}

		itemValue, err := j.decodeAny()
		if err != nil {
			return nil, err
		}

		err = j.store.ArrayAddItem(newObj, itemValue)
		if err != nil {
			return nil, err
		}

		j.skipWhitespace()

		nextChar := j.data[j.idx]
		j.idx++
		switch nextChar {
		case ']':
			return newObj, nil
		case ',':
			length++
			continue
		}
		break
	}

	return nil, fmt.Errorf("unexpected character found when decoding array value (%d)", length)
}

const (
	SS_NORMAL = iota
	SS_ESC
)

func (j *Decoder) decodeString() (interface{}, error) {
	var c byte
	var escCount int

	j.lastTypeId = JT_INVALID
	j.idx++
	startIdx := j.idx
	state := SS_NORMAL
	maxLength := int64(len(j.data))

	for {
		if j.idx >= maxLength {
			return nil, ErrIndexExceededMaximumLength
		}

		c = j.data[j.idx]
		j.idx++
		switch state {
		case SS_NORMAL:
			switch c {
			case '"':
				j.lastTypeId = JT_UTF8
				endIdx := j.idx - 1
				return j.store.NewString(j.data[startIdx:endIdx])
			case '\\':
				state = SS_ESC
				continue
			}
			if c >= 0x20 {
				continue
			}
		case SS_ESC:
			if escCount > 0 {
				if '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' {
					escCount++
					if escCount > 4 {
						state = SS_NORMAL
						escCount = 0
					}
					continue
				}
				return nil, errors.New("unexpected character " + string(c) + " in \\u hexadecimal character escape")
			}
			switch c {
			case 'b', 'f', 'n', 'r', 't', '\\', '/', '"':
				state = SS_NORMAL
				continue
			case 'u':
				escCount = 1
				continue
			}
		}
		break
	}
	return nil, errors.New("unexpected character " + string(c) + " when decoding string value")
}

func (j *Decoder) decodeNumeric() (interface{}, error) {
	startIdx := j.idx
	for {
		c := j.data[j.idx]
		switch c {
		case '-', '.', 'e', 'E', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			j.idx++
			continue
		}
		break
	}
	endIdx := j.idx
	j.lastTypeId = JT_NUMERIC
	return j.store.NewNumeric(j.data[startIdx:endIdx])
}

func (j *Decoder) decodeTrue() (interface{}, error) {
	j.idx++
	if j.data[j.idx] != 'r' {
		goto err
	}
	j.idx++
	if j.data[j.idx] != 'u' {
		goto err
	}
	j.idx++
	if j.data[j.idx] != 'e' {
		goto err
	}
	j.lastTypeId = JT_TRUE
	j.idx++
	return j.store.NewTrue()

err:
	return nil, errors.New("unexpected character found when decoding 'true'")
}

func (j *Decoder) decodeFalse() (interface{}, error) {
	j.idx++
	if j.data[j.idx] != 'a' {
		goto err
	}
	j.idx++
	if j.data[j.idx] != 'l' {
		goto err
	}
	j.idx++
	if j.data[j.idx] != 's' {
		goto err
	}
	j.idx++
	if j.data[j.idx] != 'e' {
		goto err
	}
	j.lastTypeId = JT_FALSE
	j.idx++
	return j.store.NewFalse()

err:
	return nil, errors.New("unexpected character found when decoding 'false'")
}

func (j *Decoder) decodeNull() (interface{}, error) {
	j.idx++
	if j.data[j.idx] != 'u' {
		goto err
	}
	j.idx++
	if j.data[j.idx] != 'l' {
		goto err
	}
	j.idx++
	if j.data[j.idx] != 'l' {
		goto err
	}
	j.lastTypeId = JT_NULL
	j.idx++
	return j.store.NewNull()

err:
	return nil, errors.New("unexpected character found when decoding 'null'")
}

// ===============

type simpleStore struct{}

func (s simpleStore) NewObject() (interface{}, error) {
	return make(map[string]interface{}), nil
}

func (s simpleStore) NewArray() (interface{}, error) {
	a := make([]interface{}, 0)
	return &a, nil
}

func (s simpleStore) ObjectAddKey(mi interface{}, k interface{}, v interface{}) error {
	ks := k.(string)
	m := mi.(map[string]interface{})
	m[ks] = v
	return nil
}

func (s simpleStore) ArrayAddItem(ai interface{}, v interface{}) error {
	a := ai.(*[]interface{})
	*a = append(*a, v)
	return nil
}

func (s simpleStore) NewString(b []byte) (interface{}, error) {
	str, ok := unquote(b)
	if !ok {
		return nil, errors.New("Failed to unquote string " + string(b))
	}
	return str, nil
}

func (s simpleStore) NewNumeric(b []byte) (interface{}, error) {
	return strconv.ParseFloat(string(b), 64)
}

func (s simpleStore) NewTrue() (interface{}, error) {
	return true, nil
}

func (s simpleStore) NewFalse() (interface{}, error) {
	return false, nil
}

func (s simpleStore) NewNull() (interface{}, error) {
	return nil, nil
}

// ===============

func byteToBase(b []byte, base uint64) (n uint64, err error) {
	n = 0
	for i := 0; i < len(b); i++ {
		var v byte
		d := b[i]
		switch {
		case '0' <= d && d <= '9':
			v = d - '0'
		// Update from http://golang.org/src/strconv/atoi.go?s=2131:2226#L95
		case 'a' <= d && d <= 'z':
			v = d - 'a' + 10
		case 'A' <= d && d <= 'Z':
			v = d - 'A' + 10
		default:
			return 0, fmt.Errorf("failed to convert to Base: %d", base)
		}
		n *= base
		n += uint64(v)
	}
	return n, err
}

// getu4 decodes \uXXXX from the beginning of s, returning the hex value,
// or it returns -1.
func getu4(s []byte) rune {
	if len(s) < 6 || s[0] != '\\' || s[1] != 'u' {
		return -1
	}
	r, err := byteToBase(s[2:6], 16)
	if err != nil {
		return -1
	}
	return rune(r)
}

// unquote converts a quoted JSON string literal s into an actual string t.
// The rules are different than for Go, so cannot use strconv.Unquote.
func unquote(s []byte) (t string, ok bool) {
	s, ok = unquoteBytes(s)
	t = string(s)
	return
}

func unquoteBytes(s []byte) (t []byte, ok bool) {
	// Check for unusual characters. If there are none,
	// then no unquoting is needed, so return a slice of the
	// original bytes.
	r := 0
	for r < len(s) {
		c := s[r]
		if c == '\\' || c == '"' || c < ' ' {
			break
		}
		if c < utf8.RuneSelf {
			r++
			continue
		}
		rr, size := utf8.DecodeRune(s[r:])
		if rr == utf8.RuneError && size == 1 {
			break
		}
		r += size
	}
	if r == len(s) {
		return s, true
	}

	b := make([]byte, len(s)+2*utf8.UTFMax)
	w := copy(b, s[0:r])
	for r < len(s) {
		// Out of room?  Can only happen if s is full of
		// malformed UTF-8 and we're replacing each
		// byte with RuneError.
		if w >= len(b)-2*utf8.UTFMax {
			nb := make([]byte, (len(b)+utf8.UTFMax)*2)
			copy(nb, b[0:w])
			b = nb
		}
		switch c := s[r]; {
		case c == '\\':
			r++
			if r >= len(s) {
				return
			}
			switch s[r] {
			default:
				return
			case '"', '\\', '/', '\'':
				b[w] = s[r]
				r++
				w++
			case 'b':
				b[w] = '\b'
				r++
				w++
			case 'f':
				b[w] = '\f'
				r++
				w++
			case 'n':
				b[w] = '\n'
				r++
				w++
			case 'r':
				b[w] = '\r'
				r++
				w++
			case 't':
				b[w] = '\t'
				r++
				w++
			case 'u':
				r--
				rr := getu4(s[r:])
				if rr < 0 {
					return
				}
				r += 6
				if utf16.IsSurrogate(rr) {
					rr1 := getu4(s[r:])
					if dec := utf16.DecodeRune(rr, rr1); dec != unicode.ReplacementChar {
						// A valid pair; consume.
						r += 6
						w += utf8.EncodeRune(b[w:], dec)
						break
					}
					// Invalid surrogate; fall back to replacement rune.
					rr = unicode.ReplacementChar
				}
				w += utf8.EncodeRune(b[w:], rr)
			}

		// Quote, control characters are invalid.
		case c == '"', c < ' ':
			return

		// ASCII
		case c < utf8.RuneSelf:
			b[w] = c
			r++
			w++

		// Coerce to well-formed UTF-8.
		default:
			rr, size := utf8.DecodeRune(s[r:])
			r += size
			w += utf8.EncodeRune(b[w:], rr)
		}
	}
	return b[0:w], true
}

// ==========

type JSON struct {
	root  interface{}
	Error error
}

// Stringify support map []map. not support struct, because dont use reflect.
func Stringify(v interface{}) (buf []byte, e error) {
	switch vv := v.(type) {
	case map[string]interface{}, map[string]string,
		[]map[string]interface{}, []map[string]string, []interface{}:
		buf = stringify(vv)
	case *[]map[string]interface{}:
		buf = stringify(*vv)
	case *[]map[string]string:
		buf = stringify(*vv)
	case *[]interface{}:
		buf = stringify(*vv)
	default:
		return nil, errors.New("not support types")
	}
	return
}

func stringify(v interface{}) []byte {
	var buf bytes.Buffer
	var length, i int
	switch vv := v.(type) {
	case map[string]interface{}:
		buf.WriteByte('{')
		length = len(vv)
		for k, v := range vv {
			i++
			buf.WriteString(`"` + k + `":`)
			buf.Write(stringify(v))
			if length != i {
				buf.WriteByte(',')
			}
		}
		buf.WriteByte('}')
	case map[string]string:
		buf.WriteByte('{')
		length = len(vv)
		for k, v := range vv {
			i++
			buf.WriteString(`"` + k + `":"` + v + `"`)
			if length != i {
				buf.WriteByte(',')
			}
		}
		buf.WriteByte('}')
	case []map[string]interface{}:
		length = len(vv)
		buf.WriteByte('[')
		for i := 0; i < length; i++ {
			buf.Write(stringify(vv[i]))
			if length != i+1 {
				buf.WriteByte(',')
			}
		}
		buf.WriteByte(']')
	case []map[string]string:
		length = len(vv)
		buf.WriteByte('[')
		for i := 0; i < length; i++ {
			buf.Write(stringify(vv[i]))
			if length != i+1 {
				buf.WriteByte(',')
			}
		}
		buf.WriteByte(']')
	case []interface{}:
		length = len(vv)
		buf.WriteByte('[')
		for i := 0; i < length; i++ {
			buf.Write(stringify(vv[i]))
			if length != i+1 {
				buf.WriteByte(',')
			}
		}
		buf.WriteByte(']')
	case float64, float32, int, int32, int64, int16, int8, uint, uint8, uint16, uint32, uint64, bool:
		return []byte(fmt.Sprintf("%v", vv))
	case string:
		return []byte(`"` + vv + `"`)
	case nil:
		return []byte("null")
	}
	return buf.Bytes()
}

func Parse(data []byte) (v interface{}, e error) {
	if len(data) < 2 { // Need at least "{}"
		return nil, errors.New("no data passed in")
	}

	v, e = NewDecoder(simpleStore{}, data).Decode()
	return
}

type cfg struct {
	store ObjectStore
}
type Option func(*cfg)

func WithStore(store ObjectStore) Option {
	return func(c *cfg) {
		c.store = store
	}
}

func New(data []byte, opts ...Option) (j *JSON) {
	j = &JSON{}
	var cfg = &cfg{simpleStore{}}
	for k := range opts {
		opts[k](cfg)
	}
	j.root, j.Error = NewDecoder(cfg.store, data).Decode()
	return
}

func (j *JSON) Interface() interface{} {
	return j.root
}

// Get returns a pointer to a new `Json` object
// for `key` in its `map` representation
//
// useful for chaining operations (to traverse a nested JSON):
//
//	js.Get("top_level").Get("dict").Get("value").Int()
func (j *JSON) Get(key string) *JSON {
	if j.Error != nil {
		return j
	}
	m, err := j.MaybeMap()
	if err == nil {
		if val, ok := m[key]; ok {
			return &JSON{root: val}
		}
	}
	return &JSON{root: nil}
}

// Map guarantees the return of a `map[string]interface{}` (with optional default)
//
// useful when you want to interate over map values in a succinct manner:
//
//	for k, v := range js.Get("dictionary").Map() {
//		fmt.Println(k, v)
//	}
func (j *JSON) Map(args ...map[string]interface{}) map[string]interface{} {
	if j.Error != nil {
		return nil
	}
	var def map[string]interface{}

	switch len(args) {
	case 0:
	case 1:
		def = args[0]
	default:
		log.Panicf("Map() received too many arguments %d", len(args))
	}

	a, err := j.MaybeMap()
	if err == nil {
		return a
	}

	return def
}

// MaybeMap type asserts to `map`
func (j *JSON) MaybeMap() (map[string]interface{}, error) {
	if j.Error != nil {
		return nil, j.Error
	}
	if j == nil {
		return nil, errors.New("cannot MaybeMap on a nil pointer")
	}
	if m, ok := (j.root).(map[string]interface{}); ok {
		return m, nil
	}
	return nil, errors.New("type assertion to map[string]interface{} failed")
}

// String guarantees the return of a `string` (with optional default)
//
// useful when you explicitly want a `string` in a single value return context:
//
//	myFunc(js.Get("param1").String(), js.Get("optional_param").String("my_default"))
func (j *JSON) String(args ...string) string {
	if j.Error != nil {
		return ""
	}
	var def string

	switch len(args) {
	case 0:
	case 1:
		def = args[0]
	default:
		log.Panicf("String() received too many arguments %d", len(args))
	}

	s, err := j.MaybeString()
	if err == nil {
		return s
	}

	return def
}

// MaybeString type asserts to `string`
func (j *JSON) MaybeString() (string, error) {
	if j.Error != nil {
		return "", j.Error
	}
	if s, ok := (j.root).(string); ok {
		return s, nil
	}
	return "", errors.New("type assertion to string failed")
}

// Float64 guarantees the return of an `float64` (with optional default)
//
// useful when you explicitly want an `float64` in a single value return context:
//
//	myFunc(js.Get("param1").Float64(), js.Get("optional_param").Float64(51.15))
func (j *JSON) Float64(args ...float64) float64 {
	if j.Error != nil {
		return 0
	}
	var def float64

	switch len(args) {
	case 0:
	case 1:
		def = args[0]
	default:
		log.Panicf("float64() received too many arguments %d", len(args))
	}

	i, err := j.MaybeFloat64()
	if err == nil {
		return i
	}

	return def
}

// MaybeFloat64 type asserts and parses an `float64`
func (j *JSON) MaybeFloat64() (float64, error) {
	if j.Error != nil {
		return 0, j.Error
	}
	if n, ok := (j.root).(float64); ok {
		return n, nil
	}
	return -1, errors.New("type assertion to numeric failed")
}

// Bool guarantees the return of an `bool` (with optional default)
//
// useful when you explicitly want an `bool` in a single value return context:
//
//	myFunc(js.Get("param1").Bool(), js.Get("optional_param").Bool(true))
func (j *JSON) Bool(args ...bool) bool {
	if j.Error != nil {
		return false
	}
	var def bool

	switch len(args) {
	case 0:
	case 1:
		def = args[0]
	default:
		log.Panicf("bool() received too many arguments %d", len(args))
	}

	b, err := j.MaybeBool()
	if err == nil {
		return b
	}

	return def
}

// MaybeBool type asserts and parses an `bool`
func (j *JSON) MaybeBool() (bool, error) {
	if j.Error != nil {
		return false, j.Error
	}
	if b, ok := (j.root).(bool); ok {
		return b, nil
	}
	return false, errors.New("type assertion to bool failed")
}

// Array guarantees the return of an `[]*JSON` (with optional default)
//
// useful when you explicitly want an `bool` in a single value return context:
//
//	myFunc(js.Get("param1").Array(), js.Get("optional_param").Array([]interface{}{"string", 1, 1.1, false}))
func (j *JSON) Array(args ...[]interface{}) []*JSON {
	if j.Error != nil {
		return nil
	}
	var def []*JSON

	switch len(args) {
	case 0:
	case 1:
		for _, val := range args[0] {
			def = append(def, &JSON{root: val})
		}
	default:
		log.Panicf("Array() received too many arguments %d", len(args))
	}

	a, err := j.MaybeArray()
	if err == nil {
		return a
	}

	return def
}

// MaybeArray type asserts to `*[]interface{}`
func (j *JSON) MaybeArray() ([]*JSON, error) {
	if j.Error != nil {
		return nil, j.Error
	}
	var ret []*JSON
	if a, ok := (j.root).(*[]interface{}); ok {
		for _, val := range *a {
			ret = append(ret, &JSON{root: val})
		}
		return ret, nil
	}
	return nil, errors.New("type assertion to *[]interface{} failed")
}

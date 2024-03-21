package runtimes

import (
	"bytes"
	"strings"
	"unicode"
)

// 驼峰式写法转为下划线写法
func UnderscoreName(name string) string {
	var buf bytes.Buffer
	for i, r := range name {
		if unicode.IsUpper(r) {
			if i != 0 {
				buf.WriteByte('_')
			}
			buf.WriteRune(unicode.ToLower(r))
		} else {
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

const space = ' '

// 下划线写法转为驼峰写法
func CamelName(name string) string {
	name = strings.Replace(name, "_", " ", -1)
	prev := ' '
	names := []rune(name)
	for k := range names {
		if prev == space {
			prev = names[k]
			names[k] -= 32
			continue
		}
		prev = names[k]
	}
	return strings.Replace(name, " ", "", -1)
}

package runtimes

import (
	"strings"
)

var DotSplit byte = '-'

// ParseEnvs
// user=a user-abc=1 will be {"user":{"":a, "abc":1}}
func ParseEnvs(lst []string, prefix string) (data map[string]interface{}) {
	prefix = strings.ToLower(prefix)
	data = make(map[string]interface{}, len(lst)/2)
	for _, v := range lst {
		ss := strings.Split(v, "=")
		ss[0] = strings.ToLower(ss[0])
		if strings.HasPrefix(ss[0], prefix) {
			k, v := ss[0], strings.Join(ss[1:], "=")
			setdata(data, strings.ToLower(k), v)
		}
	}
	return data
}

// ParseArgs
// user=a user-abc=1 will be {"user":{"":a, "abc":1}}
func ParseArgs(lst []string) (data map[string]interface{}) {
	// var keys, vals []string
	var key string
	data = make(map[string]interface{}, len(lst)/2)
	for k := range lst {
		if lst[k][0] == '-' && key == "" {
			key = strings.TrimPrefix(lst[k], "-")
			kk := strings.Split(key, "=")
			if len(kk) > 1 {
				setdata(data, kk[0], strings.Join(kk[1:], "="))
				key = ""
			}
			continue
		} else if lst[k][0] == '-' && key != "" {
			setdata(data, key, "true")
			key = strings.TrimPrefix(lst[k], "-")
			kk := strings.Split(key, "=")
			if len(kk) > 1 {
				setdata(data, kk[0], strings.Join(kk[1:], "="))
				key = ""
			}
			continue
		}
		if key != "" {
			setdata(data, key, lst[k])
		}
	}
	return data
}

func setdata(data map[string]interface{}, key, value string) {
	kk := strings.Split(key, string(DotSplit))
	var l = len(kk)
	for k := range kk {
		if data[kk[k]] == nil && k != l-1 {
			data[kk[k]] = make(map[string]interface{})
			data = data[kk[k]].(map[string]interface{})
			continue
		}
		if vv, ok := data[kk[k]].(map[string]interface{}); ok && k != l-1 {
			data = vv
			continue
		} else if !ok && k != l-1 {
			var temp = data[kk[k]]
			data[kk[k]] = make(map[string]interface{})
			data = data[kk[k]].(map[string]interface{})
			data[""] = temp
			continue
		}
		data[kk[k]] = value
	}
}

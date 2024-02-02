package idcard

import (
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"time"
)

const m = "10X98765432"
const a = "79:584216379:5842" // byte-48 => 7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2

type IdCard string

type Detail struct {
	AddrCode string
	Province string
	City     string
	Area     string
	Birthday string
	Male     string
}

func (s IdCard) Check() (ok bool) {
	load()
	switch len(s) {
	case 16:
		if area[string(s)[:2]+"0000"] == "" {
			return false
		}
		return true
	case 18:
		var s17 = s[17]
		if s17 == 'x' {
			s17 = 'X'
		}
		var sum int
		for i := 0; i < 17; i++ {
			sum += int((s[i] - 48)) * int(a[i]-48)
		}
		return m[sum%11] == s17
	}
	return
}

// Parse 解析身份证号中的地区信息，由于户籍迁移身份证号码不变。因此存在号码与身份证地区不一致的情况
func (s IdCard) Parse() (info Detail) {
	if !s.Check() {
		return
	}

	var no = string(s)
	info.AddrCode = no[:6]
	info.Province = area[no[:2]+"0000"]
	info.City = area[no[:4]+"00"]
	info.Area = area[no[:6]]
	var male bool
	switch len(s) {
	case 16:
		info.Birthday = "19" + no[6:8] + "-" + no[8:10] + "-" + no[10:12]
		male = (no[15]-48)%2 == 1
	case 18:
		info.Birthday = no[6:10] + "-" + no[10:12] + "-" + no[12:14]
		male = (no[17]-48)%2 == 1
	}
	if male {
		info.Male = "男"
	} else {
		info.Male = "女"
	}
	return
}

// 根据身份证号计算年龄，周岁
func (s IdCard) Age() (age int) {
	if !s.Check() {
		return -1
	}

	var year, month, day = time.Now().Date()
	var now = float64(year) + float64(month/100) + float64(day/10000)
	var birth float64
	switch len(s) {
	case 16:
		birth, _ = strconv.ParseFloat("19"+string(s)[6:12], 64)
	case 18:
		birth, _ = strconv.ParseFloat(string(s)[6:10]+"."+string(s)[10:14], 64)
	}
	return int(now - birth)
}

func randnum(max, delta int) (s string) {
	var n = rand.Intn(max) + delta
	var m = strconv.FormatInt(int64(max), 10)
	s = strconv.FormatInt(int64(n), 10)
	var slen = len(s)
	var mlen = len(m)
	if mlen == slen {
		return
	}
	for i := 0; i < mlen-slen; i++ {
		s = "0" + s
	}
	return
}

var konce sync.Once
var keys []string
var keylength int

func laodkeys() {
	load()
	konce.Do(func() {
		keylength = len(area)
		keys = make([]string, 0, keylength)
		for k := range area {
			keys = append(keys, k)
		}
	})
}

func Generate(args ...bool) (no string) {
	if len(args) > 0 && args[0] {
		laodkeys()
		no = keys[rand.Intn(keylength)]
	}
	if no == "" {
		no = randnum(54, 11)
		no += randnum(30, 1)
		no += randnum(30, 1)
	}

	var year = time.Now().Year()
	no += strconv.FormatInt(int64(year-rand.Intn(100)), 10)
	no += randnum(12, 1)
	no += randnum(29, 1)
	no += randnum(999, 0)

	fmt.Println(no)
	var sum int
	for i := 0; i < 17; i++ {
		sum += int((no[i] - 48)) * int(a[i]-48)
	}
	no += string(m[sum%11])
	return
}

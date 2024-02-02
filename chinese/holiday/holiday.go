package holiday

import (
	"time"
)

const datefmt = "2006-01-02"

type Holiday struct {
	Name string
	Is   bool
}

// Is 判断是否是节假日
func Is(ts time.Time) (ok bool) {
	v := date[ts.Format(datefmt)]
	if v.Name == "" {
		var day = ts.Weekday()
		return day == time.Sunday || day == time.Saturday
	}
	return v.Is
}

// Parse 解析获取节假日详细信息，返回详细的节日信息
func Parse(ts time.Time) (h Holiday) {
	v := date[ts.Format(datefmt)]
	if v.Name == "" {
		var day = ts.Weekday()
		h.Is = day == time.Sunday || day == time.Saturday
		return
	}
	return v
}

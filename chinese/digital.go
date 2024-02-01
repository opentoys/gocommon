package chinese

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

const zero = "零元整"
const maximum = "数位已超过最大值"

var number_map = []string{"零", "壹", "贰", "叁", "肆", "伍", "陆", "柒", "捌", "玖"}
var unit_map = []string{"", "拾", "佰", "仟"}
var big_unit_map = []string{"", "万", "亿", "兆", "京", "垓", "秭", "穰", "沟", "涧", "正", "载"} // 一、十、百、千、万、亿、兆、京、垓、秭（𥝱）、穰、沟、涧、正、载
var small_unit_map = []string{"角", "分", "厘", "毫", "丝", "忽", "微", "纤", "沙", "尘", "埃", "渺", "漠"}

func DigitalPrice(n float64) string {
	if n == 0 {
		return zero
	}
	if n >= 1e46 {
		return maximum
	}
	var s = strconv.FormatFloat(n, 'f', 13, 64)
	fmt.Println(s)
	var srr = strings.Split(s, ".")
	var integer, decimal, chinesei, chinesed string
	var zerocnt int
	integer = srr[0]
	if len(srr) > 1 {
		decimal = srr[1]
	}

	var length = len(integer)
	for i := 0; i < length; i++ {
		var num = integer[i] - 48
		var unit = length - i - 1                         // 当前数字的单位
		var quotient = int(math.Floor(float64(unit) / 4)) // 1w为进位单位, 除 4 即为 万 亿
		var remainder = unit % 4                          // 1w为进位单位, 取模 4 即为 个 十 百 千

		if num == 0 {
			zerocnt++
		} else {
			// 处理前置的零
			if zerocnt > 0 {
				chinesei += number_map[0]
			}
			zerocnt = 0
			chinesei += number_map[num] + unit_map[remainder]
		}
		if remainder == 0 && zerocnt < 4 {
			chinesei += big_unit_map[quotient]
		}
	}

	// 价格为小数时，整数部分不显示
	if n < 1 {
		chinesei = ""
	} else {
		chinesei += "元"
	}

	if len(decimal) == 0 {
		return chinesei + "整"
	}

	zerocnt = 0
	for i := 0; i < len(decimal); i++ {
		var num = decimal[i] - 48
		if num > 0 {
			if zerocnt > 0 {
				chinesed += "零"
				zerocnt = 0
			}
			chinesed += number_map[num]
			if i < 13 {
				chinesed += small_unit_map[i]
			}
		} else {
			zerocnt++
		}
	}

	return chinesei + chinesed
}

func DigitalConvert(n float64) string {
	if n == 0 {
		return "零"
	}
	if n >= math.MaxFloat64 {
		return maximum
	}
	var s = strconv.FormatFloat(n, 'f', 13, 64)
	var srr = strings.Split(s, ".")
	var integer, decimal, chinesei, chinesed string
	var zerocnt int
	integer = srr[0]
	if len(srr) > 1 {
		decimal = srr[1]
	}

	var length = len(integer)
	for i := 0; i < length; i++ {
		var num = integer[i] - 48
		var unit = length - i - 1                         // 当前数字的单位
		var quotient = int(math.Floor(float64(unit) / 4)) // 1w为进位单位, 除 4 即为 万 亿
		var remainder = unit % 4                          // 1w为进位单位, 取模 4 即为 个 十 百 千

		if num == 0 {
			zerocnt++
		} else {
			// 处理前置的零
			if zerocnt > 0 {
				chinesei += number_map[0]
			}
			zerocnt = 0
			chinesei += number_map[num] + unit_map[remainder]
		}
		if remainder == 0 && zerocnt < 4 {
			chinesei += big_unit_map[quotient]
		}
	}

	if n < 1 {
		chinesei = "零"
	}

	if len(decimal) == 0 {
		return chinesei + "整"
	}

	zerocnt = 0
	for i := 0; i < len(decimal); i++ {
		var num = decimal[i] - 48
		if num > 0 {
			if zerocnt > 0 {
				for j := 0; j < zerocnt; j++ {
					chinesed += "零"
				}
				zerocnt = 0
			}
			chinesed += number_map[num]
		} else {
			zerocnt++
		}
	}

	if len(chinesed) > 0 {
		chinesei += "点"
	}

	return chinesei + chinesed
}

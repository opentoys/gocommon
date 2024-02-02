package holiday

import (
	"testing"
	"time"
)

func TestHoliday(t *testing.T) {
	var t20240101, _ = time.Parse(datefmt, "2024-01-01")
	var t20240201, _ = time.Parse(datefmt, "2024-02-01")
	var t20240203, _ = time.Parse(datefmt, "2024-02-03")

	// today 2024-01-01
	Is(t20240101) // false

	// today 2024-02-01
	Is(t20240201)    // true
	Parse(t20240201) // {Name:"公司内部假日",Is: true}

	// today 2024-02-03
	Is(t20240203)    // true
	Parse(t20240203) // {Name:"",Is: true}

	RegisterDate(map[string]Holiday{"2024-02-01": {Name: "公司内部假日", Is: true}})

	// today 2024-01-01
	Is(t20240101) // false

	// today 2024-02-01
	Is(t20240201)    // true
	Parse(t20240201) // {Name:"公司内部假日",Is: true}

	// today 2024-02-03
	Is(t20240203)    // true
	Parse(t20240203) // {Name:"",Is: true}

	ConcatDate(map[string]Holiday{"2024-02-01": {Name: "公司内部假日", Is: true}})

	// today 2024-01-01
	Is(t20240101)    // true
	Parse(t20240101) // {Name:"元旦",Is: true}

	// today 2024-02-01
	Is(t20240201)    // true
	Parse(t20240201) // {Name:"公司内部假日",Is: true}

	// today 2024-02-03
	Is(t20240203)    // true
	Parse(t20240203) // {Name:"",Is: true}
}

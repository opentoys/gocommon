package chinese

import (
	"fmt"
	"testing"
)

func TestXxx(t *testing.T) {
	fmt.Println(DigitalConvert(1001))
	fmt.Println(DigitalPrice(99999999999999.1))
	fmt.Println(DigitalPrice("99999999999999.1"))
	fmt.Println(DigitalPrice("9999999999999999999999.112312312312312"))
}

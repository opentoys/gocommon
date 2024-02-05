package idcard

import (
	"fmt"
	"testing"
)

func TestCheck(t *testing.T) {
	for i := 0; i < 100; i++ {
		var no = Generate(true)
		var id = IdCard(no)
		fmt.Println(id, id.Check(), id.Parse(), id.Age())
	}
}

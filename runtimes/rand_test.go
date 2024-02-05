package runtimes

import (
	"fmt"
	"testing"
)

func TestRand(t *testing.T) {
	for i := 0; i < 10; i++ {
		fmt.Println(RandN(10))
		fmt.Println(Rand())
	}
}

// BenchmarkRandMod-12    	768897324	         1.529 ns/op	       0 B/op	       0 allocs/op
func BenchmarkRandMod(b *testing.B) {
	for i := 0; i < b.N; i++ {
		RandN(100)
	}
}

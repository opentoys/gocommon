package gmsm_test

import (
	"fmt"
	"io"
	"log"
	"os"
	"testing"

	"github.com/opentoys/gocommon/crypto/gmsm"
)

func TestExampleSum(t *testing.T) {
	sum := gmsm.SM3_Sum([]byte("hello world\n"))
	fmt.Printf("%x", sum)
	// Output: 4cc2036b86431b5d2685a04d289dfe140a36baa854b01cb39fcd6009638e4e7a
}

func TestExampleNew(t *testing.T) {
	h := gmsm.NewSM3()
	h.Write([]byte("hello world\n"))
	fmt.Printf("%x", h.Sum(nil))
	// Output: 4cc2036b86431b5d2685a04d289dfe140a36baa854b01cb39fcd6009638e4e7a
}

func ExampleNew_file() {
	f, err := os.Open("file.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := gmsm.NewSM3()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%x", h.Sum(nil))
}

package runtimes

import (
	"fmt"
	"os"
	"testing"
)

// "vscode":{"amd":{"entrypoint":"vs/workbench/api/node/extensionHostProcess"}}
func TestParseEnvs(t *testing.T) {
	var envs = os.Environ()
	DotSplit = '-'
	fmt.Println(envs)
	fmt.Println(Stringify(ParseEnvs(os.Environ(), "x")))
}

func TestParseArgs(t *testing.T) {
	var envs = os.Args[1:]
	DotSplit = '.'
	fmt.Println(envs)
	fmt.Println(Stringify(ParseArgs(envs)))
}

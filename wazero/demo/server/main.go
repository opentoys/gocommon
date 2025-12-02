package main

import (
	"context"
	"fmt"
	"os"

	extism "github.com/opentoys/gocommon/wazero/server"
	"github.com/tetratelabs/wazero/api"
)

func main() {
	manifest := extism.Manifest{
		AllowedHosts: []string{`baidu\.com`},
		Wasm: []extism.Wasm{
			extism.WasmFile{
				Path: "/Users/xiaqiubo/Desktop/test/go/gomcptest/wasm/libs/greet.wasm",
			},
		},
	}

	ctx := context.Background()
	config := extism.PluginConfig{EnableWasi: true}

	plugin, err := extism.NewPlugin(ctx, manifest, config, []extism.HostFunction{
		extism.NewHostFunctionWithStack("print", func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
			key, err := p.ReadString(stack[0])
			if err != nil {
				panic(err)
			}
			fmt.Println("wasm inner log: ", key)
		}, []api.ValueType{extism.ValueTypePTR}, []api.ValueType{extism.ValueTypePTR}),
		extism.NewHostFunctionWithStack("query_sql", func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
			key, err := p.ReadString(stack[0])
			if err != nil {
				panic(err)
			}
			fmt.Println("wasm inner query_sql: ", key)
			stack[0], err = p.WriteString(`{"data":"adasd"}`)
		}, []api.ValueType{extism.ValueTypePTR}, []api.ValueType{extism.ValueTypePTR}),
	})

	if err != nil {
		fmt.Printf("Failed to initialize plugin: %v\n", err)
		os.Exit(1)
	}
	_, resp, e := plugin.Call("baidu", []byte(""))
	if e != nil {
		panic(e)
	}
	fmt.Println(string(resp))
}

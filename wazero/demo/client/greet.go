package main

import (
	"encoding/json"
	"fmt"

	pdk "github.com/opentoys/gocommon/wazero/client"
)

//go:wasmexport greet
func greet() int32 {
	input := pdk.Input()
	greeting := `Hello, ` + string(input) + `!`
	pdk.OutputString(greeting)
	log(greeting)
	return 0
}

//go:wasmimport extism:host/user print
func print(uint64) uint64

func log(msg string) {
	mem := pdk.AllocateString(msg)
	defer mem.Free()
	print(mem.Offset())
}

//go:wasmexport baidu
func baidu() int32 {
	// req := pdk.NewHTTPRequest(pdk.MethodGet, "http://www.baidu.com")
	// resp := req.Send()
	// pdk.Output(resp.Body())
	var data = make(map[string]any)
	QuerySql("select * from user", &data)
	log(fmt.Sprintf("%v", data))
	// input := pdk.Input()
	// greeting := `Hello, ` + string(input) + `!`
	// pdk.OutputString(greeting)
	// log(greeting)
	return 0
}

//go:wasmimport extism:host/user query_sql
func query_sql(uint64) uint64

//go:wasmimport extism:host/user exec_sql
func exec_sql(uint64) uint64

func QuerySql(sql string, data any) (e error) {
	mem := pdk.AllocateString(sql)
	defer mem.Free()
	ptr := query_sql(mem.Offset())
	rmem := pdk.FindMemory(ptr)
	log("QuerySql data:" + string(rmem.ReadBytes()))
	e = json.Unmarshal(rmem.ReadBytes(), data)
	return
}

func ExecSql(sql string, data any) (e error) {
	mem := pdk.AllocateString(sql)
	defer mem.Free()
	ptr := exec_sql(mem.Offset())
	rmem := pdk.FindMemory(ptr)
	e = json.Unmarshal(rmem.ReadBytes(), data)
	return
}

func main() {}

// GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o wasm/libs/greet.wasm wasm/libs/greet.go

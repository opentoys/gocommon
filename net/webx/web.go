package webx

import (
	"context"
)

const StatusUnavailable = 499 // 自定义状态码

type H = map[string]any

type Handle func(context.Context) (e error)

type Route interface {
	Use(fn ...Handle)
	Group(uri string, fn ...Handle) Route
	Any(method, uri string, handle ...any)
	GET(uri string, handle ...any)
	POST(uri string, handle ...any)
	PUT(uri string, handle ...any)
	PATCH(uri string, handle ...any)
	DELETE(uri string, handle ...any)
	OPTIONS(uri string, handle ...any)
	HEAD(uri string, handle ...any)
}

type WebApp struct {
	*Trie
}

func New() *WebApp {
	var s WebApp
	s.Trie = newTrie()
	return &s
}

// 自定义成功响应类型
// 处理中可以调用 webx.Abort(ctx) 终止后续操作，自行处理响应
func (s *WebApp) SetCustomeSend(fn func(context.Context, any, error) H) {
	s.Trie.custom = fn
}

// 设置处理捕获的 panic 如何处理
func (s *WebApp) SetRecover(fn func(context.Context, any) error) {
	s.Trie.recover = fn
}

// 设置默认响应类型 默认application/json
func (s *WebApp) SetDefaultContentType(typ string) {
	s.Trie.defaultContentType = typ
}

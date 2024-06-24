package webx

import (
	"context"
	"net/http"
)

const StatusUnavailable = 499 // 自定义状态码

type H = map[string]any

type Handle func(context.Context) (e error)

type Route interface {
	http.Handler
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
	Route
}

func New(ops ...OptionStdRouter) *WebApp {
	var s WebApp
	s.Route = newStdRouter(ops...)
	return &s
}

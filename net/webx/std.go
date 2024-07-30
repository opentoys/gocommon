package webx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"reflect"
)

func newRouter() *Router {
	return &Router{
		mux:                http.NewServeMux(),
		defaultContentType: "application/json",
	}
}

type Router struct {
	prefix             string
	defaultContentType string
	mux                *http.ServeMux
	customsend         func(ctx context.Context, v any, e error) H
	recover            func(ctx context.Context, v any) error
	printroute         func(method, uri string, reflectfn reflect.Value)
	handles            []Handle
}

func (s *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var ctx = r.Context()
	var st = &store{w: w}
	ctx = context.WithValue(ctx, ctxstore{}, st)
	st.r = r.WithContext(ctx)
	s.mux.ServeHTTP(st.w, st.r)
}

func (s *Router) Use(fn ...Handle) {
	s.handles = append(s.handles, fn...)
}

func (s *Router) Group(uri string, fn ...Handle) Route {
	var app Router
	app.prefix = path.Join(s.prefix, uri)
	app.handles = append(app.handles, s.handles...)
	app.handles = append(app.handles, fn...)
	app.customsend = s.customsend
	app.recover = s.recover
	app.printroute = s.printroute
	app.defaultContentType = s.defaultContentType
	app.mux = http.NewServeMux()
	last := uri[len(uri)-1]
	if last == '/' {
		s.mux.Handle(uri, http.StripPrefix(uri[:len(uri)-1], &app))
	} else {
		s.mux.Handle(uri+"/", http.StripPrefix(uri, &app))
	}
	return &app
}

func (s *Router) Any(method, uri string, handle ...any) {
	var length = len(handle)
	var hs = make([]Handle, 0, length)
	var action = reflect.ValueOf(handle[length-1])
	var actionType = action.Type()
	var argnum = actionType.NumIn()
	var arg2 reflect.Type
	var arg2ptr bool
	if argnum > 1 {
		arg2 = actionType.In(1)
		if arg2.Kind() == reflect.Ptr {
			arg2 = arg2.Elem()
			arg2ptr = true
		}
	}
	if length > 1 {
		for _, v := range handle[:length-1] {
			if fn, ok := v.(Handle); ok {
				hs = append(hs, fn)
			}
		}
	}

	if s.printroute != nil {
		s.printroute(method, s.prefix+uri, action)
	}
	s.mux.HandleFunc(method+" "+uri, func(w http.ResponseWriter, r *http.Request) {
		var e error
		var resp any
		var ctx = r.Context()
		store := getStore(ctx)
		store.uri = s.prefix + uri
		defer func() {
			i := recover()
			if i != nil {
				if s.recover != nil {
					e = s.recover(ctx, i)
				} else {
					e = fmt.Errorf("%v", i)
				}
			}
			if e != nil {
				if s.customsend != nil {
					s.send(ctx, 0, s.customsend(ctx, nil, e))
					return
				}
				s.send(ctx, StatusUnavailable, e.Error())
				return
			}
			s.send(ctx, http.StatusOK, resp)
		}()

		if action.IsNil() {
			return
		}

		if arg2 != nil { // 有自定义参数才进行自动解析 body
			buf, _ := io.ReadAll(r.Body)
			ctx = SetRawBody(ctx, buf)
		}

		var args = []reflect.Value{reflect.ValueOf(ctx)}
		if arg2 != nil { // 初始化入参
			in := reflect.New(arg2)
			out := in.Interface()
			SetPayload(ctx, out)
			args = append(args, in)
		}

		// 调用中间件
		if e = s.rangeuse(ctx, s.handles); e != nil {
			return
		}

		if e = s.rangeuse(ctx, hs); e != nil {
			return
		}

		if store.abort {
			return
		}

		if arg2 != nil && !arg2ptr { // 如果接收参数不是指针类型，则转为非指针调用
			args[1] = reflect.Indirect(args[1])
		}
		values := action.Call(args)
		switch len(values) {
		case 1:
			if err, ok := values[0].Interface().(error); ok {
				e = err
				return
			}
		case 2:
			resp = values[0].Interface()
			e, _ = values[1].Interface().(error)
		}
	})
}

func (s *Router) rangeuse(ctx context.Context, hs []Handle) (e error) {
	store := getStore(ctx)
	for _, fn := range hs {
		if store.abort {
			return
		}
		if e = fn(ctx); e != nil {
			return
		}
		if ctx.Err() != nil {
			e = ctx.Err()
			return
		}
	}
	return
}

func (s *Router) send(ctx context.Context, code int, v any) {
	var store = getStore(ctx)
	if store.abort {
		return
	}

	encode := encode(store.w.Header().Get(headerContentType))
	switch vv := v.(type) {
	case H:
		s.writerhead(store.w, code, s.defaultContentType)
		if encode == nil {
			return
		}
		buf, _ := encode(vv)
		_, _ = store.w.Write(buf)
	case []byte:
		s.writerhead(store.w, code, http.DetectContentType(vv))
		_, _ = store.w.Write(vv)
	case string:
		s.writerhead(store.w, code, "text/plain")
		_, _ = store.w.Write([]byte(vv))
	case io.Reader:
		_, _ = io.Copy(store.w, vv)
	default:
		if store.abort || encode == nil {
			return
		}
		var resp = vv
		if s.customsend == nil {
			resp = s.customsend(ctx, vv, nil)
		}
		s.writerhead(store.w, code, s.defaultContentType)
		buf, _ := encode(resp)
		_, _ = store.w.Write(buf)
	}
}

func (s *Router) writerhead(w http.ResponseWriter, code int, ctyp string) {
	if w.Header().Get(headerContentType) == "" {
		w.Header().Set(headerContentType, ctyp)
	}
	if code > 0 {
		w.WriteHeader(code)
	}
}

func (s *Router) GET(uri string, handle ...any) {
	s.Any(http.MethodGet, uri, handle...)
}

func (s *Router) POST(uri string, handle ...any) {
	s.Any(http.MethodPost, uri, handle...)
}

func (s *Router) PUT(uri string, handle ...any) {
	s.Any(http.MethodPut, uri, handle...)
}

func (s *Router) PATCH(uri string, handle ...any) {
	s.Any(http.MethodPatch, uri, handle...)
}

func (s *Router) DELETE(uri string, handle ...any) {
	s.Any(http.MethodDelete, uri, handle...)
}

func (s *Router) OPTIONS(uri string, handle ...any) {
	s.Any(http.MethodOptions, uri, handle...)
}

func (s *Router) HEAD(uri string, handle ...any) {
	s.Any(http.MethodHead, uri, handle...)
}

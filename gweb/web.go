package gweb

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/opentoys/gocommon/runtimes"
)

type Mode uint8

const (
	Debug   Mode = 0
	Release Mode = 1
)

var ctxpool = sync.Pool{
	New: func() interface{} {
		return new(Context)
	},
}

type Engine struct {
	*Router
	timeout  time.Duration
	notfound func(*Context)
	panic    func(*Context)
	mode     Mode
}

func (s *Engine) SetMode(n Mode) {
	s.mode = n
}

type route struct {
	method  string
	uri     string
	handles int
}

// output routes register and handles count.
func (s *Engine) Graph() {
	routes := s.graph(s.children)
	var base = len(s.middleware)
	var maxmethod int
	var maxuri int
	for _, v := range routes {
		if n := len(v.method); n > maxmethod {
			maxmethod = n
		}
		if n := len(v.uri); n > maxuri {
			maxuri = n
		}
	}

	fmt.Print("Debug gweb routes...\n\n")
	var maxm = strconv.FormatInt(int64(maxmethod), 10)
	var maxu = strconv.FormatInt(int64(maxuri+5), 10)
	for _, v := range routes {
		fmt.Printf("[%-"+maxm+"s]  %-"+maxu+"s  handles(%d)\n", v.method, "/"+v.uri, base+v.handles)
	}
	fmt.Print("\n")
}

func (s *Engine) graph(router map[string]*Router) (routes []route) {
	for _, v := range router {
		rs := s.graph(v.children)
		regs := s.graph(v.regexChildren)
		unis := s.graph(v.universalChildren)
		if len(rs) > 0 {
			for _, rv := range rs {
				routes = append(routes, route{
					method:  rv.method,
					uri:     v.uri + "/" + rv.uri,
					handles: len(v.middleware) + rv.handles,
				})
			}
		}

		if len(regs) > 0 {
			for _, rv := range regs {
				routes = append(routes, route{
					method:  rv.method,
					uri:     v.uri + "/#" + rv.uri,
					handles: len(v.middleware) + rv.handles,
				})
			}
		}

		if len(unis) > 0 {
			for _, rv := range unis {
				routes = append(routes, route{
					method:  rv.method,
					uri:     v.uri + "/:" + rv.uri,
					handles: len(v.middleware) + rv.handles,
				})
			}
		}

		if (len(rs) == 0 && len(regs) == 0 && len(unis) == 0) || len(v.endless) > 0 {
			routes = append(routes, route{
				method:  v.method,
				uri:     v.uri,
				handles: len(v.middleware),
			})
		}
	}
	return
}

func (s *Engine) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	var ctx = ctxpool.Get().(*Context)
	defer s.panic(ctx)

	ctxt, cancel := context.WithTimeout(r.Context(), s.timeout)
	defer cancel()
	ctx.Request = r.WithContext(ctxt)
	ctx.Writer = rw
	ctx.params = make(map[string]string)
	ctx.QueryParams = make(map[string]string)
	ctx.middleware = ctx.middleware[:0]
	ctx.body = ctx.body[:0]
	ctx.code = 0
	ctx.nextIdx = -1
	ctx.store = make(map[interface{}]interface{})
	ctx.URI = r.URL.Path

	s.Router.find(ctx)
	ctxpool.Put(ctx)
}

type Option func(*Engine)

func WithTimeout(ts time.Duration) Option {
	return func(e *Engine) {
		e.timeout = ts
	}
}

func WithPanicHandler(fn Handler) Option {
	return func(e *Engine) {
		e.panic = fn
	}
}

func WithNotFoundHandler(fn Handler) Option {
	return func(e *Engine) {
		e.notfound = fn
	}
}

func New(args ...Option) *Engine {
	var e = &Engine{
		Router:   NewRouter(routeprefix_any, "/"),
		timeout:  time.Minute,
		notfound: DefaulteNotFound,
		panic:    DefaultePanic,
	}
	e.Router.engine = e

	for k := range args {
		args[k](e)
	}

	return e
}

var String2Bytes = func(s string) (buf []byte) {
	return []byte(s)
}

var Bytes2String = func(buf []byte) string {
	return string(buf)
}

var Stack = func(skip int) string {
	return runtimes.Stack(skip + 1)
}

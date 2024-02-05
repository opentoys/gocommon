package gweb

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

type Cache struct {
	Type     uint8 // 0: match, 1: regexp(#), 2: universal(:), 3: notfound
	Handlers []Handler
	Params   map[string]string
}

type cache map[string]*Cache

func (s cache) Set(k string, v *Cache) {
	s[k] = v
}
func (s cache) Get(k string) *Cache {
	return s[k]
}

type RouteCacher interface {
	// typ: 0: match, 1: regexp(#), 2: universal(:), 3: notfound
	Set(k string, v *Cache)
	Get(k string) *Cache
}

var RouteCahce RouteCacher = make(cache)

const (
	routeprefix_any = "ANY"
)

// Handler 定义函数类型
type Handler func(*Context)

// Router 路由类
type Router struct {
	engine            *Engine
	method            string
	uri               string
	middleware        []Handler
	children          map[string]*Router
	regexChildren     map[string]*Router
	universalChildren map[string]*Router
	endless           []Handler
}

// NewRouter 创建router
func NewRouter(method, uri string) *Router {
	uri = strings.TrimPrefix(uri, "/")
	return &Router{
		uri:               uri,
		method:            method,
		children:          make(map[string]*Router),
		regexChildren:     make(map[string]*Router),
		universalChildren: make(map[string]*Router),
		middleware:        make([]Handler, 0),
	}
}

func (s *Router) add(method, uri string, handlers ...Handler) *Router {
	us := strings.Split(strings.TrimPrefix(uri, "/"), "/")
	var nr *Router = s
	for _, v := range us {
		lr := s.get(nr.children, method, v)
		if lr != nil {
			nr = lr
			continue
		}
		// 创建临时变量
		lr = NewRouter(method, v)

		if len(v) == 0 {
			nr.children[method+"-"+v] = lr
		} else {
			switch v[0] {
			case ':': // 通配
				lr.uri = v[1:]
				nr.universalChildren[method+"-"] = lr
			case '#': // 正则
				lr.uri = v[1:]
				nr.regexChildren[method+"-"] = lr
			default: // 精准匹配
				nr.children[method+"-"+v] = lr
			}
		}
		// 依次循环创建路由
		nr = lr
	}

	if method != routeprefix_any {
		// 只挂载在最后一级路由上
		nr.endless = append(nr.endless, handlers...)
	} else {
		// 只挂载在最后一级路由上
		nr.middleware = append(nr.middleware, handlers...)
	}
	return nr
}

// Hook 挂载路由
func (s *Router) Hook(routers ...*Router) {
	for _, route := range routers {
		s.children[route.method+"-"+route.uri] = route
	}
}

// Use 中间件
func (s *Router) Use(handlers ...Handler) {
	s.middleware = append(s.middleware, handlers...)
}

// GET 请求类型
func (s *Router) GET(uri string, handlers ...Handler) {
	s.add(http.MethodGet, uri, handlers...)
}

// POST 请求类型
func (s *Router) POST(uri string, handlers ...Handler) {
	s.add(http.MethodPost, uri, handlers...)
}

func (s *Router) PUT(uri string, handlers ...Handler) {
	s.add(http.MethodPut, uri, handlers...)
}

func (s *Router) PATCH(uri string, handlers ...Handler) {
	s.add(http.MethodPatch, uri, handlers...)
}

func (s *Router) DELETE(uri string, handlers ...Handler) {
	s.add(http.MethodDelete, uri, handlers...)
}

func (s *Router) HEAD(uri string, handlers ...Handler) {
	s.add(http.MethodHead, uri, handlers...)
}

func (s *Router) OPTIONS(uri string, handlers ...Handler) {
	s.add(http.MethodOptions, uri, handlers...)
}

func (s *Router) CONNECT(uri string, handlers ...Handler) {
	s.add(http.MethodConnect, uri, handlers...)
}

func (s *Router) TRACE(uri string, handlers ...Handler) {
	s.add(http.MethodTrace, uri, handlers...)
}

func (s *Router) Method(method, uri string, handlers ...Handler) {
	s.add(method, uri, handlers...)
}

// Group 分组
func (s *Router) Group(uri string, handlers ...Handler) *Router {
	nr := s.add(routeprefix_any, uri)
	nr.middleware = append(nr.middleware, handlers...)
	return nr
}

func (s *Router) find(ctx *Context) {
	var length = len(ctx.URI)
	if length > 1 {
		if b := ctx.URI[length-1]; b == '/' {
			ctx.Redirect(ctx.URI[:length-1])
			return
		}
	}
	var rkey = ctx.Method + ctx.URI
	if v := RouteCahce.Get(rkey); v != nil {
		ctx.middleware = v.Handlers
		ctx.params = v.Params
		ctx.Next()
		return
	}

	us := strings.Split(strings.TrimPrefix(ctx.URI, "/"), "/")
	var nr *Router = s
	ctx.middleware = append(ctx.middleware, nr.middleware...)
	// 循环查找路由
	for i := 0; i < len(us); i++ {
		// 临时变量
		lr := s.get(nr.children, ctx.Method, us[i])
		// 再次, 匹配正则
		if lr == nil {
			lr = s.get(nr.regexChildren, ctx.Method, "")
			if lr != nil {
				// 解析参数
				// 编译正则, 判断是否捕获
				reg := regexp.MustCompile(lr.uri)
				if !reg.MatchString(us[i]) {
					lr = nil
				} else {
					// 获取捕获参数
					result := reg.FindStringSubmatch(us[i])
					for k, v := range reg.SubexpNames() {
						if v == "" {
							v = strconv.FormatInt(int64(k), 10)
						}
						ctx.params[v] = result[k]
					}
					ctx.typ = 1
				}
			}
		}
		// 再次, 通配
		if lr == nil {
			lr = s.get(nr.universalChildren, ctx.Method, "")
			if lr != nil {
				// 解析参数
				ctx.params[lr.uri] = us[i]
			}
			ctx.typ = 2
		}
		if lr != nil {
			ctx.middleware = append(ctx.middleware, lr.middleware...)
			if i == len(us)-1 {
				ctx.middleware = append(ctx.middleware, lr.endless...)
			}
			nr = lr
		} else {
			i = len(us)
			ctx.middleware = []Handler{s.engine.notfound}
			ctx.typ = 3
		}
	}

	RouteCahce.Set(rkey, &Cache{Handlers: ctx.middleware, Params: ctx.params, Type: ctx.typ})
	ctx.Next()
}

func (s *Router) get(children map[string]*Router, method, k string) *Router {
	if v := children[method+"-"+k]; v != nil {
		return v
	}
	return children[routeprefix_any+"-"+k]
}

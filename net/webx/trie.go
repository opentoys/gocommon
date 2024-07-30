package webx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"reflect"
	"regexp"
	"strings"
)

var regexpCache = make(map[string]*regexp.Regexp)

type Trie struct {
	defaultContentType string
	prefix             string
	uri                string
	handles            []Handle
	children           map[string]*Trie // 常规
	regex              map[string]*Trie // #xxxx
	wildcard           *Trie            // *, :id
	action             map[string]any

	custom  func(ctx context.Context, v any, e error) H
	recover func(ctx context.Context, v any) error
}

func newTrie() *Trie {
	return &Trie{
		defaultContentType: "application/json",
		prefix:             "/",
		children:           make(map[string]*Trie),
		regex:              make(map[string]*Trie),
		action:             make(map[string]any),
		recover:            func(ctx context.Context, v any) error { return nil },
	}
}

func (s *Trie) sliceAt(lst []string, i int) string {
	var max = len(lst) - 1
	if i > max || i < 0 {
		return ""
	}
	return lst[i]
}

func (s *Trie) split(uri string) (uris []string) {
	return strings.Split(strings.TrimRight(uri, "/"), "/")
}

func (s *Trie) bytes(buf string, i int) byte {
	var max = len(buf) - 1
	if i > max || i < 0 {
		return byte(0)
	}
	return buf[i]
}

func (s *Trie) byteslice(buf string, i int) string {
	var max = len(buf) - 1
	if i > max || i < 0 {
		return ""
	}
	return buf[i:]
}

func (s *Trie) regexpfind(r *http.Request, uri string, regex map[string]*Trie) *Trie {
	for k, m := range regex {
		reg := regexpCache[k]
		if reg == nil {
			return nil
		}
		if reg.MatchString(uri) {
			// 获取捕获参数
			result := reg.FindStringSubmatch(uri)
			for k, v := range reg.SubexpNames() {
				r.SetPathValue(v, result[k])
			}
			return m
		}
	}
	return nil
}

func (s *Trie) findhandle(r *http.Request, uris []string) (handles []Handle, trie *Trie) {
	trie = s
	handles = make([]Handle, 0, 8)
	var wildcard int
	for i, v := range uris {
		if trie == nil {
			return
		}

		switch s.bytes(trie.uri, 0) {
		case ':', '*':
		case '#':
			reg := regexpCache[trie.uri]
			if reg == nil || !reg.MatchString(v) {
				trie = nil
				return
			}
		default:
			if trie.uri != v {
				trie = nil
				return
			}
		}

		handles = append(handles, trie.handles...)
		v = s.sliceAt(uris, i+1)
		if v == "" && trie.children[v] == nil {
			return
		}
		if trie.children[v] != nil {
			trie = trie.children[v]
			continue
		}
		if m := s.regexpfind(r, v, trie.regex); m != nil {
			trie = m
			continue
		}
		if trie.wildcard != nil {
			wildcard = i
			trie = trie.wildcard
			r.SetPathValue(s.byteslice(trie.uri, 1), v)
			continue
		}
		if wildcard < i {
			trie = nil
		}
	}
	return
}

func (s *Trie) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var (
		handles []Handle
		st      = &store{w: w, r: r}
		ctx     = context.WithValue(r.Context(), ctxstore{}, st)
	)
	defer func() {
		if i := recover(); i != nil {
			if s.recover != nil {
				e := s.recover(ctx, i)
				s.send(ctx, http.StatusInternalServerError, e)
				return
			}
			fmt.Fprintf(w, "%v", i)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}()
	st.r = r.WithContext(ctx)

	handles, trie := s.findhandle(st.r, s.split(r.URL.Path))
	if trie == nil || trie.action[r.Method] == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	st.uri = path.Join(trie.prefix, trie.uri)
	s.covert(handles, trie.action[r.Method])(st.w, st.r)
}

func (s *Trie) Group(uri string, fn ...Handle) Route {
	var trie = s.register(uri)
	trie.handles = append(trie.handles, fn...)
	return trie
}

func (s *Trie) register(uri string) *Trie {
	var trie = s
	for _, v := range s.split(uri)[1:] {
		switch s.bytes(v, 0) {
		case '*', ':':
			if trie.wildcard == nil {
				trie.wildcard = newTrie()
				trie.wildcard.uri = v
				trie.wildcard.prefix = path.Join(trie.prefix, trie.uri)
			}
			trie = trie.wildcard
		case '#':
			regexpCache[v] = regexp.MustCompile(v[1:])
			if trie.regex[v] == nil {
				trie.regex[v] = newTrie()
				trie.regex[v].uri = v
				trie.regex[v].prefix = path.Join(trie.prefix, trie.uri)
			}
			trie = trie.regex[v]
		default:
			if trie.children[v] == nil {
				trie.children[v] = newTrie()
				trie.children[v].uri = v
				trie.children[v].prefix = path.Join(trie.prefix, trie.uri)
			}
			trie = trie.children[v]
		}
	}
	return trie
}

func (s *Trie) Use(fn ...Handle) {
	s.handles = append(s.handles, fn...)
}

func (s *Trie) Any(method, uri string, handles ...any) {
	var trie = s.register(uri)
	var max = len(handles) - 1
	for i, v := range handles {
		if fn, ok := v.(Handle); ok && i < max {
			trie.handles = append(trie.handles, fn)
			continue
		}
		if i == max {
			if trie.action[method] != nil {
				fmt.Println("method register conflict!", method, path.Join(trie.prefix, trie.uri))
			}
			trie.action[method] = v
			fmt.Println("register", method, path.Join(trie.prefix, trie.uri))
		}
	}
}

func (s *Trie) covert(handles []Handle, fn any) http.HandlerFunc {
	var action = reflect.ValueOf(fn)
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
	return func(w http.ResponseWriter, r *http.Request) {
		var e error
		var resp any
		var ctx = r.Context()
		store := getStore(ctx)
		store.uri = s.prefix + s.uri
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
				if s.custom != nil {
					s.send(ctx, 0, s.custom(ctx, nil, e))
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
		for _, v := range handles {
			e = v(ctx)
			if e != nil {
				return
			}
			if store.abort {
				return
			}
		}

		if arg2 != nil && !arg2ptr { // 如果接收参数不是指针类型，则转为非指针调用
			args[1] = reflect.Indirect(args[1])
		}
		values := action.Call(args)
		switch len(values) {
		case 1:
			if values[0].IsNil() {
				return
			}
			if err, ok := values[0].Interface().(error); ok {
				e = err
				return
			}
		case 2:
			resp = values[0].Interface()
			if !values[1].IsNil() {
				e, _ = values[1].Interface().(error)
			}
		}
	}
}

func (s *Trie) writerhead(w http.ResponseWriter, code int, ctyp string) {
	if w.Header().Get(headerContentType) == "" {
		w.Header().Set(headerContentType, ctyp)
	}
	if w.Header().Get(headerContentType) == "" {
		w.Header().Set(headerContentType, s.defaultContentType)
	}
	if code > 0 {
		w.WriteHeader(code)
	}
}

func (s *Trie) send(ctx context.Context, code int, v any) {
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
		if s.custom != nil {
			resp = s.custom(ctx, vv, nil)
		}
		s.writerhead(store.w, code, s.defaultContentType)
		buf, _ := encode(resp)
		_, _ = store.w.Write(buf)
	}
}

func (s *Trie) GET(uri string, handles ...any) {
	s.Any(http.MethodGet, uri, handles...)
}

func (s *Trie) POST(uri string, handles ...any) {
	s.Any(http.MethodPost, uri, handles...)
}

func (s *Trie) PUT(uri string, handle ...any) {
	s.Any(http.MethodPut, uri, handle...)
}

func (s *Trie) PATCH(uri string, handle ...any) {
	s.Any(http.MethodPatch, uri, handle...)
}

func (s *Trie) DELETE(uri string, handle ...any) {
	s.Any(http.MethodDelete, uri, handle...)
}

func (s *Trie) OPTIONS(uri string, handle ...any) {
	s.Any(http.MethodOptions, uri, handle...)
}

func (s *Trie) HEAD(uri string, handle ...any) {
	s.Any(http.MethodHead, uri, handle...)
}

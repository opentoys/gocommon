package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"strings"
	"time"
)

type Logger func(ctx context.Context, msg string, keyAndArgs ...any)
type BeforeRequest func(*http.Client, *http.Request) (e error)
type AfterResponse func(*http.Client, *http.Response) (e error)

type Request interface {
	R() Request
	SetHeader(k, v string) Request
	SetHeaders(headers map[string]string) Request
	SetBody(v any) Request
	SetJSON(v any) Request
	SetXML(v any) Request
	SetFormData(data map[string]string) Request
	SetMultipart(v any) Request
	SetResult(v any) Request
	SetQueryParam(k, v string) Request
	SetQueryParams(qs map[string]string) Request
	Get(ctx context.Context, url string) ([]byte, error)
	Post(ctx context.Context, url string) ([]byte, error)
	Do(ctx context.Context, method string, url string) (buf []byte, e error)
}

type Option func(*client)

func WithTimeout(ts time.Duration) Option {
	return func(c *client) {
		c.c.Timeout = ts
	}
}

func WithCookieJar(cj http.CookieJar) Option {
	return func(c *client) {
		c.c.Jar = cj
	}
}

func WithTransport(ts *http.Transport) Option {
	return func(c *client) {
		c.c.Transport = ts
	}
}

func WithLogger(log Logger) Option {
	return func(s *client) {
		s.logger = log
	}
}

func WithAfterResponse(fn AfterResponse) Option {
	return func(s *client) {
		s.afterresp = append(s.afterresp, fn)
	}
}

func WithBeforeRequest(fn BeforeRequest) Option {
	return func(s *client) {
		s.beforerequest = append(s.beforerequest, fn)
	}
}

type request struct {
	body   any
	result any
	header http.Header
	qs     url.Values
	base   string
}

type client struct {
	c             *http.Client
	logger        Logger
	r             *request
	afterresp     []AfterResponse
	beforerequest []BeforeRequest
}

func New(ops ...Option) *client {
	s := &client{
		c: &http.Client{},
		r: &request{},
	}
	for _, v := range ops {
		v(s)
	}

	return s
}

func (s *client) R() Request {
	var c = &client{
		c:      s.c,
		logger: s.logger,
		r: &request{
			body:   s.r.body,
			result: s.r.result,
			header: s.r.header,
			qs:     s.r.qs,
			base:   s.r.base,
		},
		beforerequest: append([]BeforeRequest{}, s.beforerequest...),
		afterresp:     append([]AfterResponse{}, s.afterresp...),
	}
	return c
}

func (s *client) SetHeader(k, v string) Request {
	s.r.header.Add(k, v)
	return s
}

func (s *client) log(ctx context.Context, msg string, keyAndArgs ...any) {
	if s.logger == nil {
		return
	}
	s.logger(ctx, msg, keyAndArgs...)
	return
}

func (s *client) SetHeaders(data map[string]string) Request {
	for k, v := range data {
		s.r.header.Add(k, v)
	}
	return s
}

func (s *client) SetAfterResponse(fn func(*http.Client, *http.Response) (e error)) Request {
	s.afterresp = append(s.afterresp, fn)
	return s
}

func (s *client) SetBeforeRequest(fn func(*http.Client, *http.Request) (e error)) Request {
	s.beforerequest = append(s.beforerequest, fn)
	return s
}

func (s *client) SetBody(v any) Request {
	s.r.body = v
	return s
}

func (s *client) SetJSON(v any) Request {
	s.r.header.Add("Content-Type", "application/json")
	s.r.body = v
	return s
}

func (s *client) SetXML(v any) Request {
	s.r.header.Add("Content-Type", "text/xml")
	s.r.body = v
	return s
}

func (s *client) SetFormData(data map[string]string) Request {
	s.r.header.Add("Content-Type", "application/x-www-form-urlencoded")
	var qs url.Values
	for k, v := range data {
		qs.Add(k, v)
	}
	s.r.body = qs.Encode()
	return s
}

func (s *client) SetMultipart(v any) Request {
	s.r.header.Add("Content-Type", "application/x-www-form-urlencoded")

	var buf bytes.Buffer
	var body = multipart.NewWriter(&buf)
	switch vv := v.(type) {
	case map[string]string:
		for k, v := range vv {
			w, _ := body.CreateFormField(k)
			_, _ = w.Write([]byte(v))
		}
	case *multipart.Form:
		for k, v := range vv.Value {
			for _, iv := range v {
				w, _ := body.CreateFormField(k)
				_, _ = w.Write([]byte(iv))
			}
		}
		for k, v := range vv.File {
			for _, iv := range v {
				f, e := iv.Open()
				if e != nil {
					continue
				}
				w, _ := body.CreateFormFile(k, iv.Filename)
				_, _ = io.Copy(w, f)
			}
		}
	}
	return s
}

func (s *client) SetResult(v any) Request {
	s.r.result = v
	return s
}

func (s *client) SetQueryParam(k, v string) Request {
	s.r.qs.Add(k, v)
	return s
}

func (s *client) SetQueryParams(data map[string]string) Request {
	for k, v := range data {
		s.r.qs.Add(k, v)
	}
	return s
}

func (s *client) request(ctx context.Context, method string, url string) (req *http.Request, e error) {
	if s.r.base != "" && !strings.HasPrefix(url, "http") {
		url = path.Join(s.r.base, url)
	}
	if s.r.body == nil {
		req, e = http.NewRequestWithContext(ctx, method, url, nil)
		return
	}
	switch vv := s.r.body.(type) {
	case *bytes.Buffer:
		req, e = http.NewRequestWithContext(ctx, method, url, vv)
	case []byte:
		req, e = http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(vv))
	case io.Reader:
		req, e = http.NewRequestWithContext(ctx, method, url, vv)
	case string:
		req, e = http.NewRequestWithContext(ctx, method, url, bytes.NewBufferString(vv))
	default:
		rv := reflect.ValueOf(s.r.body)
		ktyp := rv.Kind()
		if ktyp != reflect.Struct && ktyp != reflect.Map {
			e = errors.New("bad request. body format error")
			return
		}
		var buf []byte
		if strings.Contains(s.r.header.Get("Content-Type"), "xml") {
			buf, e = xml.Marshal(s.r.body)
			if e != nil {
				return
			}
			req, e = http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(buf))
			return
		}
		buf, e = json.Marshal(s.r.body)
		if e != nil {
			return
		}
		req, e = http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(buf))
	}
	return
}

func (s *client) Do(ctx context.Context, method string, url string) (buf []byte, e error) {
	req, e := s.request(ctx, method, url)
	if e != nil {
		return
	}

	for _, fn := range s.beforerequest {
		if e = fn(s.c, req); e != nil {
			return
		}
	}

	var start = time.Now()
	s.log(ctx, "request", map[string]any{
		"header": req.Header,
		"body":   req.Body,
		"url":    req.URL,
		"method": req.Method,
	}, "http request")

	var resp *http.Response
	defer func() {
		if resp == nil {
			s.log(ctx, "response", map[string]any{
				"url":    req.URL,
				"method": req.Method,
				"error":  e.Error(),
				"time":   time.Since(start),
			}, "http response")
			return
		}
		s.log(ctx, "response", map[string]any{
			"url":    req.URL,
			"method": req.Method,
			"header": resp.Header,
			"body":   string(buf),
			"code":   resp.StatusCode,
			"time":   time.Since(start),
		}, "http response")
	}()

	resp, e = s.c.Do(req)
	if e != nil {
		return
	}
	for _, fn := range s.afterresp {
		if e = fn(s.c, resp); e != nil {
			return
		}
	}

	buf, e = io.ReadAll(resp.Body)
	return
}

func (s *client) Get(ctx context.Context, url string) ([]byte, error) {
	return s.Do(ctx, http.MethodGet, url)
}

func (s *client) Post(ctx context.Context, url string) ([]byte, error) {
	return s.Do(ctx, http.MethodPost, url)
}

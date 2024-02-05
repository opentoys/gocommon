package gweb

import (
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"time"
)

type Context struct {
	code       int
	nextIdx    int
	body       []byte
	params     map[string]string
	middleware []Handler
	*http.Request
	Writer http.ResponseWriter
	typ    uint8 //  0: match, 1: regexp(#), 2: universal(:), 3: notfound

	URI         string
	QueryParams map[string]string
	store       map[interface{}]interface{}
}

func (s *Context) Header(k string) string {
	return s.Request.Header.Get(k)
}

func (s *Context) Redirect(uri string) {
	s.Writer.Header().Set("Location", uri)
	s.Writer.WriteHeader(307)
	s.Write(nil)
}

func (s *Context) Cookie(k string) string {
	c, e := s.Request.Cookie(k)
	if e != nil {
		return ""
	}
	return c.Value
}

func (s *Context) SetCookie(cookie *http.Cookie) {
	http.SetCookie(s.Writer, cookie)
}

func (s *Context) SetHeader(k, v string) {
	s.Writer.Header().Add(k, v)
}

func (s *Context) Deadline() (deadline time.Time, ok bool) {
	return s.Request.Context().Deadline()
}

func (s *Context) Done() <-chan struct{} {
	return s.Request.Context().Done()
}

func (s *Context) Err() error {
	return s.Request.Context().Err()
}

func (s *Context) Value(key interface{}) interface{} {
	return s.store[key]
}

func (s *Context) Set(key, v interface{}) {
	s.store[key] = v
}

func (s *Context) Param(k string) (v string) {
	return s.params[k]
}

func (s *Context) BindJSON(v interface{}) (e error) {
	return json.Unmarshal(s.Body(), v)
}

func (s *Context) BindXML(v interface{}) (e error) {
	return xml.Unmarshal(s.Body(), v)
}

func (s *Context) Body() []byte {
	if s.body == nil {
		s.body, _ = io.ReadAll(s.Request.Body)
		if s.body == nil {
			s.body = []byte{}
		}
	}
	return s.body
}

func (c *Context) Next() {
	c.nextIdx++
	if c.nextIdx >= len(c.middleware) {
		return
	}
	c.middleware[c.nextIdx](c)
}

func (s *Context) Code(code int) {
	s.code = code
}

func (s *Context) Send(v interface{}) {
	if s.code == 0 {
		s.code = http.StatusOK
	}

	switch vv := v.(type) {
	case []byte:
		s.Writer.WriteHeader(s.code)
		s.Writer.Write(vv)
	case string:
		s.Writer.WriteHeader(s.code)
		s.Writer.Write(String2Bytes(vv))
	case *ErrCode:
		s.Writer.WriteHeader(http.StatusOK)
		s.Writer.Write(String2Bytes(vv.Msg))
	case error:
		s.Writer.WriteHeader(http.StatusInternalServerError)
		s.Writer.Write(String2Bytes(vv.Error()))
	default:
		buf, e := json.Marshal(v)
		if e != nil {
			s.Writer.WriteHeader(http.StatusInternalServerError)
			s.Writer.Write(String2Bytes(e.Error()))
			return
		}
		s.Writer.WriteHeader(s.code)
		s.Writer.Write(buf)
	}
}

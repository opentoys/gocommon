package webx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"time"
)

type ctxstore struct{}

type store struct {
	body    any
	session any
	w       http.ResponseWriter
	r       *http.Request
	uri     string
	raw     []byte
	abort   bool
}

func getStore(ctx context.Context) *store {
	return ctx.Value(ctxstore{}).(*store)
}

func GetRequest(ctx context.Context) *http.Request {
	v := ctx.Value(ctxstore{})
	if v != nil {
		return v.(*store).r
	}
	return nil
}

func GetRawURI(ctx context.Context) string {
	v := ctx.Value(ctxstore{})
	if v != nil {
		return v.(*store).uri
	}
	return ""
}

func GetResponse(ctx context.Context) http.ResponseWriter {
	v := ctx.Value(ctxstore{})
	if v != nil {
		return v.(*store).w
	}
	return nil
}

func GetOriginResponse(ctx context.Context) http.ResponseWriter {
	v := ctx.Value(ctxstore{})
	if v != nil {
		s := v.(*store)
		if w, ok := s.w.(*writer); ok {
			return w.ResponseWriter
		}
		return s.w
	}
	return nil
}

func GetCustomResponse(ctx context.Context) http.ResponseWriter {
	v := ctx.Value(ctxstore{})
	if v != nil {
		s := v.(*store)
		if w, ok := s.w.(*writer); ok {
			return w.buf
		}
	}
	return nil
}

func SetResponse(ctx context.Context, w http.ResponseWriter) {
	v := ctx.Value(ctxstore{})
	if v != nil {
		s := v.(*store)
		s.w = &writer{ResponseWriter: s.w, buf: w}
	}
}

func GetRawBody(ctx context.Context) []byte {
	v := ctx.Value(ctxstore{})
	if v != nil {
		return v.(*store).raw
	}
	return nil
}

func SetRawBody(ctx context.Context, body []byte) context.Context {
	v := ctx.Value(ctxstore{})
	if v != nil {
		v.(*store).raw = body
	}
	return ctx
}

func GetPayload(ctx context.Context) (body any) {
	v := ctx.Value(ctxstore{})
	if v != nil {
		return v.(*store).body
	}
	return
}

func SetPayload(ctx context.Context, body any) {
	v := ctx.Value(ctxstore{})
	if v != nil {
		v.(*store).body = body
	}
}

func SetSession(ctx context.Context, v any) {
	cs := ctx.Value(ctxstore{})
	if cs != nil {
		cs.(*store).session = v
	}
}

func GetSession(ctx context.Context) (v any) {
	cs := ctx.Value(ctxstore{})
	if cs != nil {
		v = cs.(*store).session
	}
	return
}

func Abort(ctx context.Context) {
	v := ctx.Value(ctxstore{})
	if v != nil {
		v.(*store).abort = true
	}
}

func IsAbort(ctx context.Context) bool {
	v := ctx.Value(ctxstore{})
	if v != nil {
		return v.(*store).abort
	}
	return false
}

func UsePayload() Handle {
	return func(ctx context.Context) (e error) {
		var body = GetPayload(ctx)
		if body == nil {
			return
		}
		var buf = GetRawBody(ctx)
		var r = GetRequest(ctx)
		_ = FormEncoded(r.URL.Query(), body, "qs")
		_ = FormEncoded(r.Header, body, "header")
		var ctyp = r.Header.Get(headerContentType)
		e = decode(ctyp)(buf, body)
		return
	}
}

func UseLogger(printf func(string, ...any)) Handle {
	return func(ctx context.Context) (e error) {
		var start = time.Now()
		var r = GetRequest(ctx)
		SetResponse(ctx, httptest.NewRecorder())
		go func() {
			<-ctx.Done()
			var w = GetCustomResponse(ctx)
			ws := w.(*httptest.ResponseRecorder)
			printf("%s [%s] %d %s %s (%s)\n", time.Now().Format(time.DateTime), r.Method, ws.Code, ws.Body.String(), r.RequestURI, time.Since(start))
		}()
		return
	}
}

type writer struct {
	http.ResponseWriter
	buf http.ResponseWriter
}

func (s *writer) WriteHeader(statusCode int) {
	if s.buf != nil {
		s.buf.WriteHeader(statusCode)
	}
	s.ResponseWriter.WriteHeader(statusCode)
}

func (s *writer) Write(p []byte) (n int, err error) {
	if s.buf != nil {
		_, _ = s.buf.Write(p)
	}
	return s.ResponseWriter.Write(p)
}

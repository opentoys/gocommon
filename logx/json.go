package logx

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
)

type jsonhandler struct {
	Out    io.Writer
	Err    io.Writer
	Option *slog.HandlerOptions
	attrs  []slog.Attr
}

var _ slog.Handler = &jsonhandler{}

type Option func(*jsonhandler)

func WithErrorWriter(w io.Writer) Option {
	return func(h *jsonhandler) {
		h.Err = w
	}
}

func WithLevel(level slog.Level) Option {
	return func(h *jsonhandler) {
		h.Option.Level = level
	}
}

func WithAddSource(add bool) Option {
	return func(h *jsonhandler) {
		h.Option.AddSource = add
	}
}

func WithReplaceAttr(fn func(groups []string, a slog.Attr) slog.Attr) Option {
	return func(h *jsonhandler) {
		h.Option.ReplaceAttr = fn
	}
}

func New(o io.Writer, opts ...Option) *jsonhandler {
	if o == nil {
		o = io.Discard
	}
	var s jsonhandler
	s.Option = &slog.HandlerOptions{}
	s.Out = o
	for _, v := range opts {
		v(&s)
	}
	if s.Err == nil {
		s.Err = s.Out
	}
	return &s
}

func (s *jsonhandler) clone() *jsonhandler {
	return &jsonhandler{
		Out:    s.Out,
		Err:    s.Err,
		Option: s.Option,
		attrs:  s.attrs,
	}
}

func (s *jsonhandler) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= s.Option.Level.Level()
}

func (s *jsonhandler) Handle(ctx context.Context, r slog.Record) (e error) {
	if !s.Enabled(ctx, r.Level) {
		return
	}
	var msg = map[string]any{
		"msg":   r.Message,
		"time":  r.Time.String(),
		"level": r.Level.String(),
	}

	r.Attrs(func(v slog.Attr) bool {
		msg[v.Key] = v.Value.Any()
		return false
	})

	for _, v := range s.attrs {
		msg[v.Key] = v.Value.Any()
	}

	var enc *json.Encoder
	if r.Level == slog.LevelError && s.Err != nil {
		enc = json.NewEncoder(s.Err)
	} else {
		enc = json.NewEncoder(s.Out)
	}
	enc.SetEscapeHTML(false)
	e = enc.Encode(msg)
	return
}

func (s *jsonhandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	a := s.clone()
	a.attrs = append(a.attrs, attrs...)
	return a
}

func (s *jsonhandler) WithGroup(name string) slog.Handler {
	return s.clone()
}

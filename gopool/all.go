package gopool

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"
)

type Logger func(ctx context.Context, format string, args ...interface{})

type all struct {
	max     int32
	log     Logger
	ctx     context.Context
	timeout time.Duration
	cancel  func()
}

type AllOption func(*all)

func WithAllLogger(log Logger) AllOption {
	return func(a *all) {
		a.log = log
	}
}

func WithAllMax(max int32) AllOption {
	return func(a *all) {
		a.max = max
	}
}

func WithAllContext(ctx context.Context) AllOption {
	return func(a *all) {
		a.ctx = ctx
	}
}

func WithAllTimeout(ts time.Duration) AllOption {
	return func(a *all) {
		a.timeout = ts
	}
}

func NewAll(opts ...AllOption) *all {
	var a all
	for k := range opts {
		opts[k](&a)
	}

	if a.ctx == nil {
		a.ctx = context.Background()
	}

	if a.timeout > 0 {
		a.ctx, a.cancel = context.WithTimeout(a.ctx, a.timeout)
	}
	return &a
}

func (s *all) Cancel() {
	s.cancel()
}

func (s *all) Run(fns ...func(ctx context.Context) error) (err error) {
	s.ctx, s.cancel = context.WithCancel(s.ctx)
	defer s.cancel()
	var n, en int32
	var length = len(fns)
	var ch = make(chan struct{})

	for i := range fns {
		func(i int) {
			async(func() {
				defer func() {
					atomic.AddInt32(&n, 1)
					if i := recover(); i != nil && atomic.SwapInt32(&en, 1) == 0 {
						err = fmt.Errorf("panic: %v", i)
						ch <- struct{}{}
						return
					}

					if n == int32(length) && atomic.SwapInt32(&en, 1) == 0 {
						ch <- struct{}{}
						return
					}
				}()

				e := fns[i](s.ctx)
				if e != nil && atomic.SwapInt32(&en, 1) == 0 {
					err = e
					ch <- struct{}{}
					return
				}
			}, WithGoLogger(s.log))
		}(i)
	}

	<-ch
	close(ch)
	return
}

type gopt struct {
	log Logger
	ctx context.Context
}

type GoOption func(*gopt)

func WithGoLogger(log Logger) GoOption {
	return func(g *gopt) {
		if log != nil {
			g.log = log
		}
	}
}

func WithGoContext(ctx context.Context) GoOption {
	return func(g *gopt) {
		if ctx != nil {
			g.ctx = ctx
		}
	}
}

func async(fn func(), opts ...GoOption) {
	var opt gopt
	for k := range opts {
		opts[k](&opt)
	}
	Go(func() {
		defer func() {
			i := recover()
			if i != nil && opt.log != nil {
				opt.log(opt.ctx, "安全协程执行失败: %v", i)
			}
		}()
		fn()
	})
}

// Go will be replace your custom async go
var Go = func(fn func()) {
	go func() {
		fn()
	}()
}

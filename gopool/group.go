// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package errgroup provides synchronization, error propagation, and Context
// cancelation for groups of goroutines working on subtasks of a common task.
//
// [errgroup.Group] is related to [sync.WaitGroup] but adds handling of tasks
// returning errors.
package gopool

import (
	"context"
	"fmt"
	"sync"
)

type token struct{}

// A Group is a collection of goroutines working on subtasks that are part of
// the same overall task.
//
// A zero Group is valid, has no limit on the number of active goroutines,
// and does not cancel on error.
type Group struct {
	wg      sync.WaitGroup
	cancel  func()
	sem     chan token
	errOnce sync.Once
	err     error
}

func (g *Group) done() {
	if i := recover(); i != nil {
		g.errOnce.Do(func() {
			g.err = fmt.Errorf("group error panic: %v", i)
			if g.cancel != nil {
				g.cancel()
			}
		})
	}
	if g.sem != nil {
		<-g.sem
	}
	g.wg.Done()
}

// WithContext returns a new Group and an associated Context derived from ctx.
//
// The derived Context is canceled the first time a function passed to Go
// returns a non-nil error or the first time Wait returns, whichever occurs
// first.
func WithContext(ctx context.Context) *Group {
	_, cancel := context.WithCancel(ctx)
	return &Group{cancel: cancel}
}

// Wait blocks until all function calls from the Go method have returned, then
// returns the first non-nil error (if any) from them.
func (g *Group) Wait() error {
	g.wg.Wait()
	if g.cancel != nil {
		g.cancel()
	}
	return g.err
}

// Go calls the given function in a new goroutine.
// It blocks until the new goroutine can be added without the number of
// active goroutines in the group exceeding the configured limit.
//
// The first call to return a non-nil error cancels the group's context, if the
// group was created by calling WithContext. The error will be returned by Wait.
func (g *Group) Go(f func() error) {
	if g.sem != nil {
		g.sem <- token{}
	}

	g.wg.Add(1)
	Go(func() {
		defer g.done()

		if err := f(); err != nil {
			g.errOnce.Do(func() {
				g.err = err
				if g.cancel != nil {
					g.cancel()
				}
			})
		}
	})
}

// SetLimit limits the number of active goroutines in this group to at most n.
// A negative value indicates no limit.
//
// Any subsequent call to the Go method will block until it can add an active
// goroutine without exceeding the configured limit.
//
// The limit must not be modified while any goroutines in the group are active.
func (g *Group) SetLimit(n int) {
	if n < 0 {
		g.sem = nil
		return
	}
	if len(g.sem) != 0 {
		return
	}
	g.sem = make(chan token, n)
}

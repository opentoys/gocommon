package gweb

import (
	"fmt"
	"strings"

	"github.com/opentoys/gocommon/runtimes"
)

type ErrCode struct {
	Code  int32
	Msg   string
	stack []string
	errs  []error
}

func (s *ErrCode) Error() string {
	return s.Msg
}

func (s *ErrCode) String() string {
	return strings.Join(append([]string{s.Msg}, s.stack...), "\n\t")
}

func (s *ErrCode) Format(args ...interface{}) *ErrCode {
	return &ErrCode{stack: s.stack, errs: s.errs, Msg: fmt.Sprintf(s.Msg, args...)}
}

func (s *ErrCode) Is(e error) bool {
	for k := range s.errs {
		if e == s.errs[k] {
			return true
		}
	}
	return false
}

func (s *ErrCode) Unwrap() error {
	if len(s.errs) == 0 {
		return s
	}
	return s.errs[len(s.errs)-1]
}

func NewError(code int32, args ...interface{}) *ErrCode {
	return &ErrCode{}
}

func ErrorWrap(e error) error {
	if ev, ok := e.(*ErrCode); ok {
		ev.errs = append(ev.errs, e)
		ev.Msg = e.Error()
		return ev
	}
	return &ErrCode{Msg: e.Error(), errs: []error{e}}
}

func ErrorStack(e error) error {
	if ev, ok := e.(*ErrCode); ok {
		ev.errs = append(ev.errs, e)
		ev.stack = append(ev.stack, runtimes.Stack(2))
		ev.Msg = e.Error()
		return ev
	}
	return &ErrCode{Msg: e.Error(), stack: []string{runtimes.Stack(2)}, errs: []error{e}}
}

var ErrUnkonw = &ErrCode{Code: -1, Msg: "未知错误: %s"}

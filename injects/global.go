package injects

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

type Config struct {
	Name string // name
	Step Step   // step 越小，执行越靠前
}

type Step uint8

var Service = NewInjects()

func NewInjects() *global {
	return &global{
		g: &Graph{logger: log{}},
	}
}

type object struct {
	o *Object
	S Step
}

type global struct {
	wg   sync.RWMutex
	data []*object
	g    *Graph
}

func (s *global) SetFullpath(t bool) {
	s.g.fullpath = true
}

func (s *global) SetDebug(t bool) {
	s.g.debug = true
}

func (s *global) Register(v interface{}, cfgs ...*Config) {
	s.wg.Lock()
	defer s.wg.Unlock()
	if len(cfgs) == 0 {
		cfgs = append(cfgs, &Config{})
	}
	// 第一个名字是别名 Object{}.Name
	var item = &Object{Value: v}
	item.Name = cfgs[0].Name
	s.data = append(s.data, &object{o: item, S: cfgs[0].Step})
}

func (s *global) Action() (e error) {
	s.wg.RLock()
	defer s.wg.RUnlock()
	for idx := range s.data {
		if e = s.g.Provide(s.data[idx].o); e != nil {
			return
		}
	}

	if e = s.g.Populate(); e != nil {
		return
	}

	var sb strings.Builder
	sb.WriteString("action inject register func\n")
	sort.Slice(s.data, func(i, j int) bool {
		return s.data[i].S < s.data[j].S
	})
	var arr []string
	var by Step = 255
	for idx := range s.data {
		if by != s.data[idx].S {
			sb.WriteString(fmt.Sprintf("    [step %d]: %v\n", by, arr))
			arr = []string{}
			by = s.data[idx].S
		}
		arr = append(arr, s.data[idx].o.String())
		if v, ok := s.data[idx].o.Value.(interface{ Register() (e error) }); ok {
			if e = v.Register(); e != nil {
				return
			}
		}
	}
	sb.WriteString(fmt.Sprintf("    run at %d: %v\n", by, arr))
	if s.g.debug {
		s.g.logger.Debugf(sb.String())
	}
	return
}

func (s *global) FindObjects(prefix string) (lst []interface{}) {
	s.wg.RLock()
	defer s.wg.RUnlock()
	for idx := range s.data {
		if strings.HasPrefix(s.data[idx].o.Name, prefix) {
			lst = append(lst, s.data[idx].o.Value)
		}
	}
	return
}

type log struct{}

func (log) Debugf(format string, v ...interface{}) {
	format += "\n"
	fmt.Printf(format, v...)
}

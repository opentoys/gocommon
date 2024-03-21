//go:build !go1.18
// +build !go1.18

package runtimes

type Set map[interface{}]struct{}

func NewSet(a ...interface{}) Set {
	s := make(Set, len(a))
	for i := range a {
		s.Set(a[i])
	}
	return s
}

func (s *Set) Set(k interface{}) {
	(*s)[k] = struct{}{}
}

func (s *Set) Count() int {
	return len(*s)
}

func (s *Set) Has(k interface{}) (ok bool) {
	_, ok = (*s)[k]
	return
}

func (s *Set) Delete(k interface{}) {
	delete((*s), k)
}

func (s *Set) Clear() {
	*s = make(Set)
}

func (s *Set) ForEach(fn func(v interface{})) {
	for v := range *s {
		fn(v)
	}
}

func (s *Set) Keys() (lst []interface{}) {
	for k := range *s {
		lst = append(lst, k)
	}
	return
}

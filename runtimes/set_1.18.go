//go:build go1.18
// +build go1.18

package runtimes

type Set[T comparable] map[T]struct{}

func NewSet[T comparable](a ...T) *Set[T] {
	s := make(Set[T], len(a))
	for i := range a {
		s.Set(a[i])
	}
	return &s
}

func (s *Set[T]) Set(k T) {
	(*s)[k] = struct{}{}
}

func (s *Set[T]) Count() int {
	return len(*s)
}

func (s *Set[T]) Has(k T) (ok bool) {
	_, ok = (*s)[k]
	return
}

func (s *Set[T]) Delete(k T) {
	delete((*s), k)
}

func (s *Set[T]) Clear() {
	*s = make(Set[T])
}

func (s *Set[T]) ForEach(fn func(v T)) {
	for v := range *s {
		fn(v)
	}
}

func (s *Set[T]) Keys() (lst []T) {
	for k := range *s {
		lst = append(lst, k)
	}
	return
}

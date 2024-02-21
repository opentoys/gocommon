package gopool

func AllWithLimit(max int, fns ...func() (e error)) (e error) {
	var g Group
	g.SetLimit(max)
	for _, v := range fns {
		g.Go(v)
	}
	return g.Wait()
}

func All(fns ...func() (e error)) (e error) {
	return AllWithLimit(-1, fns...)
}

// Go will be replace your custom async go
var Go = func(fn func()) {
	go func() {
		defer recover()
		fn()
	}()
}

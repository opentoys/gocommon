# gweb
`gweb` is a lightweight, only relation standard library for build HTTP services.

## install 
```
go get -u github.com/opentoys/gcommon/gweb
```

## Features
- Lightweight - only relation standard library
- Regular routing - Support regular expression route matching and fuzzy matching
- 100% compatible with net/http - use any http or middleware pkg in the ecosystem that is also compatible with net/http
- Designed for modular/composable APIs - middlewares, inline middlewares, route groups and sub-router mounting
- Context control - built on new context package, providing value chaining, cancellations and timeouts
- Robust - in production at Pressly, Cloudflare, Heroku, 99Designs, and many others (see discussion)
- Go.mod support - as of v5, go.mod support (see CHANGELOG)
- No external dependencies - plain ol' Go stdlib + net/http

## Examples
```go 
	app := gweb.New()

	app.Use(func(ctx *gweb.Context) {
		fmt.Println("req start")
		ctx.Next()
		fmt.Println("resp end")
	})

	app.GET("/hello", func(ctx *gweb.Context) {
		ctx.Send("ok")
	})

	app.Method(http.MethodPut, "/hello/1/123/234/123", func(ctx *gweb.Context) {
		ctx.Send("hello put")
	})

	group := app.Group("/group", gweb.DefaultePanic)
	group.POST("/nihao", func(ctx *gweb.Context) {
		ctx.Send("nihao")
	})

	group.GET("/images/:id", func(ctx *gweb.Context) {
		ctx.Send("nihao")
	})

	group.GET("/files/#(^.*)txt$", func(ctx *gweb.Context) {
		ctx.Send("file txt")
	})

    // will print route register
    // [PUT ]  /hello/1/123/234/123       handles(2)
    // [POST]  /group/nihao               handles(3)
    // [GET ]  /group/images/:id          handles(3)
    // [GET ]  /group/files/#^.*txt$      handles(3)
    // [GET ]  /hello                     handles(2)
	app.Graph()

	http.ListenAndServe(":12345", app)
```
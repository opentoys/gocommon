package gweb_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/opentoys/gocommon/gweb"
)

func handle(ctx *gweb.Context) {
	fmt.Println("req start")
	ctx.Next()
	fmt.Println("resp end")
}

func TestGWeb(t *testing.T) {
	app := gweb.New()

	app.Use(handle)

	app.GET("/hello", func(ctx *gweb.Context) {
		ctx.Send("ok")
	})

	app.GET("/hello/1/123/234/123", func(ctx *gweb.Context) {
		ctx.Send("hello put")
	})

	group := app.Group("/group", handle)
	group.POST("/nihao", func(ctx *gweb.Context) {
		ctx.Send("nihao")
	})

	group.GET("/images/:id", func(ctx *gweb.Context) {
		ctx.Send("nihao" + ctx.Param("id"))
	})

	group.Group("user/:id").GET(`/files/#(?P<file>^.*)\.txt$`, handle, func(ctx *gweb.Context) {
		ctx.Send("file txt" + ctx.Param("0"))
	})

	app.Graph()

	http.ListenAndServe(":12345", app)
}

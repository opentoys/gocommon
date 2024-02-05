package gweb

import (
	"fmt"
	"net/http"
)

func DefaulteNotFound(ctx *Context) {
	ctx.Code(http.StatusNotFound)
	ctx.Writer.Write([]byte("NotFound"))
}

func DefaultePanic(ctx *Context) {
	if i := recover(); i != nil {
		ctx.Code(http.StatusInternalServerError)
		ctx.Writer.Write([]byte(fmt.Sprintf("Panic: %v", i)))
	}
}

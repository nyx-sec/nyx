package main

import (
	"os"
	"os/exec"

	"github.com/gin-gonic/gin"
)

type Input struct {
	Path string
	Cmd  string
}

// The gin context is recognised by its declared type, not the name `c`.
func queryByCtx(ctx *gin.Context) {
	f := ctx.Query("f")
	exec.Command(f).Run()
}

// The embedded *http.Request field is a request too.
func headerByField(c *gin.Context) {
	h := c.Request.Header.Get("X-Cmd")
	exec.Command(h).Run()
}

// Binders decode the request into their pointer argument.
func bindJSON(c *gin.Context) {
	var in Input
	if err := c.ShouldBindJSON(&in); err != nil {
		return
	}
	os.ReadFile(in.Path)
}

func bindLegacy(c *gin.Context) {
	var in Input
	c.BindJSON(&in)
	exec.Command(in.Cmd).Run()
}

// The binder's only return value is the error, which carries no request data.
func bindErrorEcho(c *gin.Context) {
	var in Input
	if err := c.ShouldBindJSON(&in); err != nil {
		c.String(400, err.Error())
		return
	}
}

func main() {
	r := gin.Default()
	r.GET("/a", queryByCtx)
	r.GET("/b", headerByField)
	r.POST("/c", bindJSON)
	r.POST("/d", bindLegacy)
	r.POST("/e", bindErrorEcho)
	r.Run()
}

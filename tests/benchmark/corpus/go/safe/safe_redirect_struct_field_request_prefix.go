package main

import (
	"net/http"
)

// A request context that carries the request and the writer as fields.
type Context struct {
	Req  *http.Request
	Resp http.ResponseWriter
}

func redirectInsideApp(ctx *Context) {
	section := ctx.Req.URL.Query().Get("section")
	target := "/app/" + section
	http.Redirect(ctx.Resp, ctx.Req, target, http.StatusFound)
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		redirectInsideApp(&Context{Req: r, Resp: w})
	})
	_ = http.ListenAndServe(":8080", nil)
}

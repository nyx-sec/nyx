package main

import (
	"net/http"
)

// A request context that carries the request and the writer as fields.
type Context struct {
	Req  *http.Request
	Resp http.ResponseWriter
}

func redirectToQuery(ctx *Context) {
	next := ctx.Req.URL.Query().Get("next")
	http.Redirect(ctx.Resp, ctx.Req, next, http.StatusFound)
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		redirectToQuery(&Context{Req: r, Resp: w})
	})
	_ = http.ListenAndServe(":8080", nil)
}

package main

import (
	"net/http"
	"os/exec"
)

// A request context that carries the request and the writer as fields.
type Context struct {
	Req  *http.Request
	Resp http.ResponseWriter
}

type handler struct {
	r *http.Request
}

func runFromQuery(ctx *Context) {
	name := ctx.Req.URL.Query().Get("cmd")
	exec.Command("sh", "-c", name).Run()
}

func runFromHeader(ctx Context) {
	name := ctx.Req.Header.Get("X-Cmd")
	exec.Command(name).Run()
}

// A method receiver brings its fields too.
func (h *handler) runFromForm() {
	name := h.r.FormValue("cmd")
	exec.Command("sh", "-c", name).Run()
}

func main() {
	http.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		runFromQuery(&Context{Req: r, Resp: w})
		runFromHeader(Context{Req: r, Resp: w})
		(&handler{r: r}).runFromForm()
	})
	_ = http.ListenAndServe(":8080", nil)
}

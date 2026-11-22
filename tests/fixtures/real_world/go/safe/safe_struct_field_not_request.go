package main

import (
	"net/http"
	"os/exec"
)

// `Req` is a plain field here, not a request.
type Job struct {
	Req  *LoadRequest
	Name string
}

type LoadRequest struct {
	Header map[string]string
}

// A struct declared with a request field, used through a formal of another
// type that has a field of the same name.
type Context struct {
	Req *http.Request
}

type Other struct {
	Req Tag
}

type Tag struct{}

func (Tag) Get(string) string { return "ls" }

func runJob(job *Job) {
	name := job.Req.Header["name"]
	exec.Command("sh", "-c", name).Run()
}

func runOther(ctx *Other) {
	name := ctx.Req.Get("cmd")
	exec.Command(name).Run()
}

func shadowed(ctx *Context) {
	// An inner formal named ctx of another type shadows the outer one.
	run := func(ctx *Other) {
		name := ctx.Req.Get("cmd")
		exec.Command(name).Run()
	}
	run(&Other{})
}

func main() {
	http.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		runJob(&Job{Name: "x"})
		runOther(&Other{})
		shadowed(&Context{Req: r})
	})
	_ = http.ListenAndServe(":8080", nil)
}

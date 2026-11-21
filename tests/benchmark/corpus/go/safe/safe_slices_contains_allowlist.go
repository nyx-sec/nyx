package main

import (
	"net/http"
	"os/exec"
	"slices"
)

var allowed = []string{"ls", "pwd"}

func run(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	if !slices.Contains(allowed, cmd) {
		return
	}
	exec.Command(cmd).Run()
}

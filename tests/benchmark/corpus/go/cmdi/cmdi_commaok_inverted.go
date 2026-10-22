package main

import (
	"net/http"
	"os/exec"
)

var allowed = map[string]bool{"ls": true, "pwd": true}

func run(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	if _, ok := allowed[cmd]; ok {
		return
	}
	exec.Command("sh", "-c", cmd).Run()
}

package main

import (
	"net/http"
	"os/exec"
	"slices"
)

var blocked = []string{"rm", "shutdown"}

func run(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	if slices.Contains(blocked, cmd) {
		return
	}
	exec.Command(cmd).Run()
}

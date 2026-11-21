package main

import (
	"net/http"
	"os/exec"
)

// The range iterable is a request accessor; each value reaches the shell.
func handler(w http.ResponseWriter, r *http.Request) {
	for _, v := range r.URL.Query()["cmd"] {
		exec.Command("sh", "-c", v).Run()
	}
	w.WriteHeader(http.StatusOK)
}

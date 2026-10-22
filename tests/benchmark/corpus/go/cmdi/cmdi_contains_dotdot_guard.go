package main

import (
	"net/http"
	"os/exec"
	"strings"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// A `..` check does not remove shell metacharacters.
	if strings.Contains(name, "..") {
		http.Error(w, "bad", 400)
		return
	}
	exec.Command("sh", "-c", "cat "+name).Run()
}

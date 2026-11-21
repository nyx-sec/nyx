package main

import (
	"net/http"
	"os/exec"
	"strings"
)

func stripSemicolon(s string) string {
	return strings.ReplaceAll(s, ";", "")
}

func ping(w http.ResponseWriter, r *http.Request) {
	host := stripSemicolon(r.URL.Query().Get("host"))
	exec.Command("sh", "-c", "ping -c 1 "+host).Run()
}

func firstPipeOnly(w http.ResponseWriter, r *http.Request) {
	host := strings.Replace(r.URL.Query().Get("host"), "|", "", 1)
	exec.Command("sh", "-c", "ping -c 1 "+host).Run()
}

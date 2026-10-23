package main

import (
	"net/http"
	"os/exec"
	"strings"
)

// strip removes ';' only; '|', '&&' and '$(...)' still reach the shell.
func strip(s string) string {
	return strings.ReplaceAll(s, ";", "")
}

func handler(w http.ResponseWriter, r *http.Request) {
	host := strip(r.URL.Query().Get("host"))
	_ = exec.Command("sh", "-c", "ping -c 1 "+host).Run()
}

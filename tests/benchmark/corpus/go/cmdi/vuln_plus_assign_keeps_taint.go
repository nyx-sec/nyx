// Appending a literal flag with `+=` keeps the query value in `cmd`.
package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	cmd += " --verbose"
	exec.Command("sh", "-c", cmd).Run()
}

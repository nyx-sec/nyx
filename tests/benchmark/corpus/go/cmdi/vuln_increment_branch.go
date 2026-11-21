// `i++` makes i 1, so the branch runs.  Without the increment statement as
// a definition, `i == 1` folded false against the initial 0.
package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	i := 0
	i++
	if i == 1 {
		exec.Command("sh", "-c", cmd).Run()
	}
}

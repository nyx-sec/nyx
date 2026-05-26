// Phase 17 (Track L.15) — chi CMDI vuln fixture.
//
// The /run route forwards a `cmd` query parameter straight into
// `os/exec.Command`.  Adapter binding: `r.Get("/run", Run)` with
// `cmd` flowing through the request query.
package main

import (
	"fmt"
	"net/http"
	"os/exec"

	"github.com/go-chi/chi/v5"
)

func Run(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	fmt.Print("__NYX_SINK_HIT__\n")
	out, _ := exec.Command("sh", "-c", cmd).CombinedOutput()
	fmt.Print(string(out))
	_, _ = w.Write([]byte("ok"))
}

func main() {
	r := chi.NewRouter()
	r.Get("/run", Run)
	_ = r
}

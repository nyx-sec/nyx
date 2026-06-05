// Phase 17 (Track L.15) — chi benign control fixture.
package main

import (
	"net/http"
	"os/exec"

	"github.com/go-chi/chi/v5"
)

func Run(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	allow := map[string]string{"ls": "ls", "ps": "ps"}
	if safe, ok := allow[cmd]; ok {
		_ = exec.Command(safe).Run()
	}
	_, _ = w.Write([]byte("ok"))
}

func main() {
	r := chi.NewRouter()
	r.Get("/run", Run)
	_ = r
}

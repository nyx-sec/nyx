// net/http handler.  The `(w http.ResponseWriter, r *http.Request)`
// signature marks `Handler` as a `GoNetHttp` entry point.  Seeding
// policy: the bare `r` object is NOT painted as `Source` (would FP
// on `r.Context()` / `r.WithContext(...)` lifecycle access).
// Adversary bytes surface via the global Go label rules at
// `src/labels/go.rs`: `r.FormValue`, `r.URL.Query`,
// `r.URL.Query.Get`, `r.Header.Get`, `r.Body`, `r.Cookie` all
// classify as `Source(Cap::all())`.  `name := r.URL.Query().Get("name")`
// produces a tainted local that flows through `exec.Command`
// (a SHELL_ESCAPE sink), firing `taint-unsanitised-flow` with
// `r.URL.Query` as the source attribution.
package handlers

import (
	"net/http"
	"os/exec"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	cmd := exec.Command("echo", name)
	_ = cmd.Run()
	_ = w
}

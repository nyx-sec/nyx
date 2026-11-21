package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

// Fixture: a Go switch with 6+ cases, each dispatching to a different
// sink. Designed to exercise multi-case taint propagation — we assert
// the engine reports findings across distinct cases regardless of
// whether the SSA terminator uses the classic cascade or the
// Terminator::Switch variant.
//
// The user input `r.URL.Query().Get("q")` picks the case and a second
// input, `target`, flows into a different dangerous sink per switch case.
// Switching on `action` itself would not do: inside `case "login":` the
// value is the literal "login", so no case would carry attacker data.
// Cases are mutually exclusive (Go switch has no implicit fall-through) so
// the Switch terminator is a natural fit.

var db *sql.DB

func dispatch(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("q")
	target := r.URL.Query().Get("target")

	switch action {
	case "login":
		// SQL injection: target flows into a raw query.
		db.Query("SELECT * FROM users WHERE name = '" + target + "'")
	case "ping":
		// Command injection via exec.
		exec.Command("sh", "-c", "ping "+target).Run()
	case "render":
		// XSS: reflected back to response writer.
		fmt.Fprintf(w, "<div>%s</div>", target)
	case "read":
		// Path traversal: open an attacker-controlled file.
		os.Open(target)
	case "env":
		// Environment tampering.
		os.Setenv(target, "1")
	case "log":
		// Log injection via %s echo of tainted input.
		fmt.Fprintf(os.Stderr, "%s", target)
	case "stream":
		// Additional SSRF-shaped HTTP fetch.
		http.Get(target)
	default:
		fmt.Fprint(w, "unknown")
	}
}

func main() {
	http.HandleFunc("/", dispatch)
	http.ListenAndServe(":8080", nil)
}

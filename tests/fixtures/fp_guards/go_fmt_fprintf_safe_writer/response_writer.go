package main

import (
	"fmt"
	"net/http"
)

// renderResponse keeps the canonical XSS sink shape: tainted user input
// flows into `http.ResponseWriter` via `fmt.Fprintf`.  This MUST still fire
// `taint-unsanitised-flow` with HTML_ESCAPE caps, the writer-aware
// suppression must not over-clear when the writer IS a response stream.
func renderResponse(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<h1>hello %s</h1>", name)
}

// Safe: query value routed through the project-local `stripCRLF` helper
// before being written to the response header.
package main

import (
	"net/http"
	"strings"
)

func stripCRLF(raw string) string {
	return strings.ReplaceAll(strings.ReplaceAll(raw, "\r", ""), "\n", "")
}

func handler(w http.ResponseWriter, r *http.Request) {
	lang := r.URL.Query().Get("lang")
	safe := stripCRLF(lang)
	w.Header().Set("X-Lang", safe)
}

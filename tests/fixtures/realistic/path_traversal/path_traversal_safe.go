// Phase 13 path-traversal sanitized (Go).  Canonicalises the path via
// `filepath.Clean(filepath.Join(base, name))` (existing
// `Sanitizer(FILE_IO)` rule on `filepath.Clean`) and validates
// containment with `strings.HasPrefix(candidate, base)` before serving the
// file with `http.ServeFile` (FILE_IO sink on the name argument).  The root
// ends with a separator: without it the prefix test also admits a sibling
// directory such as `/var/data-x`.
package handlers

import (
	"net/http"
	"path/filepath"
	"strings"
)

func SafeHandle(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	base := "/var/data/"
	candidate := filepath.Clean(filepath.Join(base, name))
	if !strings.HasPrefix(candidate, base) {
		http.Error(w, "escape", 400)
		return
	}
	http.ServeFile(w, r, candidate)
}

// Phase 13 path-traversal sanitized (Go).  Canonicalises the path via
// `filepath.Clean(filepath.Join(base, name))` (existing
// `Sanitizer(FILE_IO)` rule on `filepath.Clean`) and validates
// containment with `strings.HasPrefix(candidate, base)`.  The canonical
// path is written as a response body, not a FILE_IO sink.
package handlers

import (
	"net/http"
	"path/filepath"
	"strings"
)

func SafeHandle(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	base := "/var/data"
	candidate := filepath.Clean(filepath.Join(base, name))
	if !strings.HasPrefix(candidate, base) {
		http.Error(w, "escape", 400)
		return
	}
	w.Write([]byte(candidate))
}

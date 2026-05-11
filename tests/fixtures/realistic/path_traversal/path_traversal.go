// Phase 13 path-traversal positive (Go).  net/http handler reads
// `r.URL.Query().Get("name")` (Source) and feeds the value into
// `os.ReadFile` (existing FILE_IO sink in `src/labels/go.rs`,
// re-exercised here under the path-traversal cross-language test).
package handlers

import (
	"net/http"
	"os"
)

func Handle(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	data, _ := os.ReadFile(name)
	w.Write(data)
}

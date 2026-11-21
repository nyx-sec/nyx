package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func download(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("f")
	// Join cleans its result, so the prefix check is a containment test.
	p := filepath.Join("/srv/data", name)
	if !strings.HasPrefix(p, "/srv/data/") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	f, err := os.Open(p)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	io.Copy(w, f)
}

package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func download(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("f")
	// Cleaning a rooted path folds every `..` against `/`, so the join below
	// cannot climb out of /var/data.
	clean := filepath.Clean("/" + name)
	p := filepath.Join("/var/data", clean)
	f, err := os.Open(p)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	io.Copy(w, f)
}

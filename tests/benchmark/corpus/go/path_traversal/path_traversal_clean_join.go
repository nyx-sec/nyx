package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func download(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("f")
	// Clean is lexical: `../../etc/passwd` keeps its leading `..`.
	clean := filepath.Clean(name)
	f, err := os.Open(filepath.Join("/data", clean))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	io.Copy(w, f)
}

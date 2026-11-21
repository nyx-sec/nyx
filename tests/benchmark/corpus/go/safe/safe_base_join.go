package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func download(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("f")
	leaf := filepath.Base(name)
	f, err := os.Open(filepath.Join("/data", leaf))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	io.Copy(w, f)
}

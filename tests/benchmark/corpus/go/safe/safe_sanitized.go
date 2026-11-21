package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	if !is_authenticated(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	path := r.URL.Query().Get("path")
	clean := filepath.Clean(path)
	f, err := os.Open(clean)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	defer f.Close()
	io.Copy(w, f)
}

func is_authenticated(r *http.Request) bool {
	return r.Header.Get("Authorization") != ""
}

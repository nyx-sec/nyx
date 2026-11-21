package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func sanitizePath(p string) string {
	return filepath.Clean(p)
}

func handler(w http.ResponseWriter, r *http.Request) {
	if !is_authenticated(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	path := r.URL.Query().Get("path")
	f, err := os.Open(sanitizePath(path))
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

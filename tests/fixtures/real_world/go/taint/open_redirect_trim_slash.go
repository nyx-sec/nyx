package main

import (
	"net/http"
	"strings"
)

// Trimming only forward slashes still lets `/\evil.example` through: browsers
// read `/\` as a protocol-relative reference.
func redirectTrimForwardOnly(w http.ResponseWriter, r *http.Request) {
	target := "/" + strings.Trim(r.URL.Path, "/")
	http.Redirect(w, r, target, http.StatusFound)
}

// TrimRight never touches the start of the path, so `//evil.example` survives.
func redirectTrimRightOnly(w http.ResponseWriter, r *http.Request) {
	target := "/" + strings.TrimRight(r.URL.Path, "/\\")
	http.Redirect(w, r, target, http.StatusFound)
}

// Removing backslashes does not stop a leading `//`.
func redirectBackslashOnly(w http.ResponseWriter, r *http.Request) {
	clean := strings.ReplaceAll(r.URL.Path, `\`, "/")
	target := "/" + clean
	http.Redirect(w, r, target, http.StatusFound)
}

func main() {
	http.HandleFunc("/a", redirectTrimForwardOnly)
	http.HandleFunc("/b", redirectTrimRightOnly)
	http.HandleFunc("/c", redirectBackslashOnly)
	_ = http.ListenAndServe(":8080", nil)
}

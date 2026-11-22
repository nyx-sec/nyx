package main

import (
	"net/http"
	"strings"
)

// Trimming only forward slashes still lets `/\evil.example` through: browsers
// read `/\` as a protocol-relative reference.
func redirectTrimmed(w http.ResponseWriter, r *http.Request) {
	target := "/" + strings.Trim(r.URL.Path, "/")
	http.Redirect(w, r, target, http.StatusFound)
}

func main() {
	http.HandleFunc("/", redirectTrimmed)
	_ = http.ListenAndServe(":8080", nil)
}

package main

import (
	"fmt"
	"net/http"
	"strings"
)

// The cutset holds both separators and every character a URL parser drops
// (C0 controls, space), so the character after the leading `/`
// is neither `/` nor `\`.
func redirectTrimBoth(w http.ResponseWriter, r *http.Request) {
	target := "/" + strings.Trim(r.URL.Path, "/\\\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20")
	http.Redirect(w, r, target, http.StatusFound)
}

// TrimLeft through an intermediate name.
func redirectTrimLeftNamed(w http.ResponseWriter, r *http.Request) {
	clean := strings.TrimLeft(r.URL.Path, "/\\\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20")
	target := "/" + clean
	http.Redirect(w, r, target, http.StatusFound)
}

// Backslashes are rewritten first, so trimming `/` leaves no separator at the
// front; the query is appended after the locked head.
func redirectNormalizeThenTrim(w http.ResponseWriter, r *http.Request) {
	path := strings.ReplaceAll(r.URL.Path, `\`, `/`)
	target := "/" + strings.Trim(path, "/\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20")
	if r.URL.RawQuery != "" {
		target = fmt.Sprintf("%s?%s", target, r.URL.RawQuery)
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func main() {
	http.HandleFunc("/a", redirectTrimBoth)
	http.HandleFunc("/b", redirectTrimLeftNamed)
	http.HandleFunc("/c", redirectNormalizeThenTrim)
	_ = http.ListenAndServe(":8080", nil)
}

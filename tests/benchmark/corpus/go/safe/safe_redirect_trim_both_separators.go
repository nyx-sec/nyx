package main

import (
	"net/http"
	"strings"
)

// The cutset holds both separators and every character a URL parser drops
// (C0 controls, space), so whatever follows the leading `/` is
// neither `/` nor `\` and the redirect stays on this origin.
func redirectTrimmed(w http.ResponseWriter, r *http.Request) {
	target := "/" + strings.Trim(r.URL.Path, "/\\\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20")
	http.Redirect(w, r, target, http.StatusFound)
}

func main() {
	http.HandleFunc("/", redirectTrimmed)
	_ = http.ListenAndServe(":8080", nil)
}

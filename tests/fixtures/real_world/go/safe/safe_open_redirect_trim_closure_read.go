package main

import (
	"net/http"
	"strings"
)

func log(string) {}

// The closure only reads the locked value, so the lock stands.
func redirectClosureRead(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("next")
	p := "/" + strings.Trim(q, "/\\\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20")
	note := func() { log(p) }
	note()
	http.Redirect(w, r, p, http.StatusFound)
}

func main() {
	http.HandleFunc("/", redirectClosureRead)
	_ = http.ListenAndServe(":8080", nil)
}

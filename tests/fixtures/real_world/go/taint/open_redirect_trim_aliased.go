package main

import (
	"net/http"
	"strings"
)

// The closure overwrites the locked value before the redirect runs.
func redirectClosureWrite(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("next")
	p := "/" + strings.Trim(q, "/\\\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20")
	f := func() { p = q }
	f()
	http.Redirect(w, r, p, http.StatusFound)
}

func overwrite(dst *string, v string) { *dst = v }

// A pointer argument lets the callee overwrite the locked value.
func redirectPointerWrite(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("next")
	p := "/" + strings.Trim(q, "/\\\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20")
	overwrite(&p, q)
	http.Redirect(w, r, p, http.StatusFound)
}

func main() {
	http.HandleFunc("/a", redirectClosureWrite)
	http.HandleFunc("/b", redirectPointerWrite)
	_ = http.ListenAndServe(":8080", nil)
}

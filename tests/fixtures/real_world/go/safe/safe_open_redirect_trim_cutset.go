package main

import (
	"fmt"
	"net/http"
	"strings"
)

// The cutset holds both separators, so the character after the leading `/`
// is neither `/` nor `\`.
func redirectTrimBoth(w http.ResponseWriter, r *http.Request) {
	target := "/" + strings.Trim(r.URL.Path, "/\\")
	http.Redirect(w, r, target, http.StatusFound)
}

// TrimLeft through an intermediate name.
func redirectTrimLeftNamed(w http.ResponseWriter, r *http.Request) {
	clean := strings.TrimLeft(r.URL.Path, "/\\")
	target := "/" + clean
	http.Redirect(w, r, target, http.StatusFound)
}

// Backslashes are rewritten first, so trimming `/` leaves no separator at the
// front; the query is appended after the locked head.
func redirectNormalizeThenTrim(w http.ResponseWriter, r *http.Request) {
	path := strings.ReplaceAll(r.URL.Path, `\`, `/`)
	target := "/" + strings.Trim(path, "/")
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

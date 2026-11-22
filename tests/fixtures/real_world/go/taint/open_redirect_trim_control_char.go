package main

import (
	"fmt"
	"net/http"
	"strings"
)

// Trim removes both separators but not a tab: ?next=%09/evil.example gives
// "/\t/evil.example", which a browser reads as //evil.example.
func redirectTrimSeparatorsOnly(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("next")
	target := "/" + strings.Trim(q, "/\\")
	http.Redirect(w, r, target, http.StatusFound)
}

// The same through fmt.Sprintf.
func redirectSprintfTrim(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("next")
	target := fmt.Sprintf("/%s", strings.Trim(q, "/\\"))
	http.Redirect(w, r, target, http.StatusFound)
}

// A backslash rewrite then Trim of '/' leaves the tab as well.
func redirectNormalizeThenTrim(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("next")
	path := strings.ReplaceAll(q, `\`, `/`)
	target := "/" + strings.Trim(path, "/")
	http.Redirect(w, r, target, http.StatusFound)
}

func main() {
	http.HandleFunc("/a", redirectTrimSeparatorsOnly)
	http.HandleFunc("/b", redirectSprintfTrim)
	http.HandleFunc("/c", redirectNormalizeThenTrim)
	_ = http.ListenAndServe(":8080", nil)
}

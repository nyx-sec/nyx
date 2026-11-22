package main

import (
	"net/http"
	"strings"
)

// The cutset holds both separators, so whatever follows the leading `/` is
// neither `/` nor `\` and the redirect stays on this origin.
func redirectTrimmed(w http.ResponseWriter, r *http.Request) {
	target := "/" + strings.Trim(r.URL.Path, "/\\")
	http.Redirect(w, r, target, http.StatusFound)
}

func main() {
	http.HandleFunc("/", redirectTrimmed)
	_ = http.ListenAndServe(":8080", nil)
}

package handler

import "net/http"

// Unsafe: query arg flows directly into http.Redirect (3rd arg URL).
func Unsafe(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("next")
	http.Redirect(w, r, target, http.StatusFound)
}

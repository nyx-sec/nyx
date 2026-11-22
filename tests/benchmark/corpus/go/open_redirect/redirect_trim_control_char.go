package main

import (
	"net/http"
	"strings"
)

// A tab survives the Trim: ?next=%09/evil.example gives "/\t/evil.example".
func h(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("next")
	target := "/" + strings.Trim(q, "/\\")
	http.Redirect(w, r, target, http.StatusFound)
}

func main() {
	http.HandleFunc("/", h)
	_ = http.ListenAndServe(":8080", nil)
}

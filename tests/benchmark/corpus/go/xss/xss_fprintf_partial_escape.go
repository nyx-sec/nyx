package main

import (
	"fmt"
	"html"
	"net/http"
)

func profile(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	bio := r.URL.Query().Get("bio")
	fmt.Fprintf(w, "<h1>%s</h1><p>%s</p>", html.EscapeString(name), bio)
}

func main() {
	http.HandleFunc("/profile", profile)
	http.ListenAndServe(":8080", nil)
}

package main

import (
	"fmt"
	"html"
	"net/http"
)

func partial(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	bio := r.URL.Query().Get("bio")
	fmt.Fprintf(w, "<h1>%s</h1><p>%s</p>", html.EscapeString(name), bio)
}

func escaped(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	bio := r.URL.Query().Get("bio")
	fmt.Fprintf(w, "<h1>%s</h1><p>%s</p>", html.EscapeString(name), html.EscapeString(bio))
}

func main() {
	http.HandleFunc("/partial", partial)
	http.HandleFunc("/escaped", escaped)
	http.ListenAndServe(":8080", nil)
}

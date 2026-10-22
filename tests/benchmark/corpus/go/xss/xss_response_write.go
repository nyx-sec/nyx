package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Write([]byte("<h1>Hello " + name + "</h1>"))
}

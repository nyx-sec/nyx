package main

import (
	"io"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	io.WriteString(w, "<h1>Hello "+name+"</h1>")
}

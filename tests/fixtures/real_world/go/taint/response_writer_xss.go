package main

import (
	"fmt"
	"io"
	"net/http"
)

func writeBytes(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	w.Write([]byte("<h1>" + q + "</h1>"))
}

func writeInline(rw http.ResponseWriter, r *http.Request) {
	rw.Write([]byte(r.FormValue("q")))
}

func fprint(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	fmt.Fprint(w, q)
}

func fprintln(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	fmt.Fprintln(w, q)
}

func writeString(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	io.WriteString(w, q)
}

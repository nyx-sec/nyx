package main

import (
	"net/http"
	"strings"
)

func bodyOnly(w http.ResponseWriter, r *http.Request) {
	b := r.FormValue("b")
	c := &http.Client{}
	c.Post("https://api.example.com/v1/items", "application/json", strings.NewReader(b))
}

func responseHeader(w http.ResponseWriter, r *http.Request) {
	resp, _ := http.Get("https://api.example.com/v1/status")
	v := resp.Header.Get(r.FormValue("k"))
	_ = v
}

func fixedHost(w http.ResponseWriter, r *http.Request) {
	c := &http.Client{}
	c.Get("https://api.example.com/search?q=" + r.FormValue("q"))
}

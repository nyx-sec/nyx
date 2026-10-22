package main

import (
	"net/http"
	"strings"
	"time"
)

func localClient(w http.ResponseWriter, r *http.Request) {
	c := &http.Client{Timeout: time.Second}
	resp, _ := c.Get(r.URL.Query().Get("u"))
	_ = resp
}

func valueClient(w http.ResponseWriter, r *http.Request) {
	u := r.FormValue("u")
	var c http.Client
	c.Head(u)
}

func formalClient(client *http.Client, w http.ResponseWriter, r *http.Request) {
	u := r.FormValue("u")
	client.Post(u, "application/json", nil)
}

func forwardAuth(w http.ResponseWriter, r *http.Request) {
	c := &http.Client{}
	req, _ := http.NewRequest("POST", "https://audit.example.com/log", strings.NewReader(r.Header.Get("Authorization")))
	c.Do(req)
}

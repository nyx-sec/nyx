package main

import (
	"fmt"
	"net/http"
	"net/url"
)

const apiBase = "https://api.example.com/"

// Safe: `scheme://host/` head on a short declaration.
func shortDecl(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	u := "https://inventory.internal/api/items/" + id
	resp, _ := http.Get(u)
	resp.Body.Close()
}

// Safe: the same on a `var` declaration.
func varDecl(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	var u = "https://inventory.internal/api/items/" + id
	resp, _ := http.Get(u)
	resp.Body.Close()
}

// Safe: a left-nested concatenation keeps the head.
func nestedConcat(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	u := "https://inventory.internal/api/items/" + id + "/details"
	resp, _ := http.Get(u)
	resp.Body.Close()
}

// Safe: format string with a fixed head.
func sprintfURL(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	u := fmt.Sprintf("https://inventory.internal/api/items/%s", id)
	resp, _ := http.Get(u)
	resp.Body.Close()
}

// Safe: the URL is the second argument of NewRequest.
func newRequest(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	req, _ := http.NewRequest("GET", "https://inventory.internal/api/items/"+id, nil)
	http.DefaultClient.Do(req)
}

// Safe: module-level constant base.
func constBase(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	resp, _ := http.Get(apiBase + id)
	resp.Body.Close()
}

// Safe: JoinPath appends segments, so no element can change the host.
func joinPath(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("p")
	u, _ := url.JoinPath("https://api.example.com", p)
	resp, _ := http.Get(u)
	resp.Body.Close()
}

// Vulnerable: the URL is the request parameter.
func rawURL(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("u")
	resp, _ := http.Get(u)
	resp.Body.Close()
}

// Vulnerable: attacker-controlled host in a NewRequest URL.
func newRequestRaw(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("u")
	req, _ := http.NewRequest("GET", u, nil)
	http.DefaultClient.Do(req)
}

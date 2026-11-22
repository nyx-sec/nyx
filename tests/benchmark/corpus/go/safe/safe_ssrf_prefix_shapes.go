package main

import (
	"fmt"
	"net/http"
)

const apiBase = "https://api.example.com/"

func lookup(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	var u = "https://inventory.internal/api/items/" + name + "/details"
	resp, _ := http.Get(u)
	resp.Body.Close()
}

func request(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	req, _ := http.NewRequest("GET", fmt.Sprintf("https://inventory.internal/api/items/%s", name), nil)
	http.DefaultClient.Do(req)
}

func constBase(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	resp, _ := http.Get(apiBase + name)
	resp.Body.Close()
}

package main

import (
	"net/http"
	"os"
)

type LoadRequest struct {
	Body string
	Form string
}

// `req` is not an *http.Request, so `req.Body` is a plain struct field.
func loadSpec(req *LoadRequest) {
	os.ReadFile(req.Body)
}

// The closure's own `req` formal shadows the handler's request.
func handler(w http.ResponseWriter, req *http.Request) {
	load := func(req *LoadRequest) {
		os.ReadFile(req.Form)
	}
	load(&LoadRequest{Form: "/etc/app.conf"})
}

// An outbound request built locally is not request input.
func fetchConfig() {
	req, _ := http.NewRequest("GET", "https://config.internal/v1", nil)
	os.ReadFile(req.Header.Get("X-Config-Path"))
}

func main() {
	http.HandleFunc("/", handler)
	loadSpec(&LoadRequest{Body: "/etc/spec.json"})
	fetchConfig()
	http.ListenAndServe(":8080", nil)
}

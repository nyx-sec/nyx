package main

import (
	"net/http"
	"time"
)

func proxy(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

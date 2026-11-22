package main

import (
	"net/http"
	"strings"
)

func IsHostnameInternal(host string) bool {
	return host == "localhost" || strings.HasPrefix(host, "10.")
}

// Internal hosts are rejected before the request is built.
func handler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if IsHostnameInternal(host) {
		http.Error(w, "internal host", http.StatusBadRequest)
		return
	}
	http.Get("https://" + host + "/hook")
}

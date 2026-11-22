package main

import (
	"net/http"
	"strings"
)

func IsHostnameInternal(host string) bool {
	return host == "localhost" || strings.HasPrefix(host, "10.")
}

// The request sits on the edge where the host is internal, so the denylist
// call guards nothing.
func handler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if IsHostnameInternal(host) {
		http.Get("https://" + host + "/hook")
	}
}

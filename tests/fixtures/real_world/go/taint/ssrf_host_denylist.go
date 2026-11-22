package main

import (
	"net/http"
	"os/exec"
	"strings"
)

func IsHostnameInternal(host string) bool {
	return host == "localhost" || strings.HasPrefix(host, "10.")
}

func IsLocalFile(name string) bool {
	return strings.HasPrefix(name, "file:")
}

// The denylist call rejects internal hosts and the handler returns early.
func rejectEarly(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if IsHostnameInternal(host) {
		http.Error(w, "internal host", http.StatusBadRequest)
		return
	}
	http.Get("https://" + host + "/hook") // @safe internal hosts were rejected
}

// Negated form: the request is made only when the host is not internal.
func negatedForm(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if !IsHostnameInternal(host) {
		http.Get("https://" + host + "/hook") // @safe internal hosts were rejected
	}
}

// The request sits on the edge where the host is internal.
func rejectEdgeRequest(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if IsHostnameInternal(host) {
		http.Get("https://" + host + "/hook") // @vuln runs only for internal hosts
	}
}

// A predicate about something else does not vouch for the host.
func unrelatedPredicate(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if IsLocalFile(host) {
		return
	}
	http.Get("https://" + host + "/hook") // @vuln no host check
}

// The denylist covers SSRF only, not command injection.
func otherSink(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if IsHostnameInternal(host) {
		return
	}
	exec.Command("sh", "-c", "ping "+host).Run() // @vuln denylist does not stop shell injection
}

// No check at all.
func unguarded(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	http.Get("https://" + host + "/hook") // @vuln
}

func main() {
	http.HandleFunc("/a", rejectEarly)
	http.HandleFunc("/b", negatedForm)
	http.HandleFunc("/c", rejectEdgeRequest)
	http.HandleFunc("/d", unrelatedPredicate)
	http.HandleFunc("/e", otherSink)
	http.HandleFunc("/f", unguarded)
	http.ListenAndServe(":8080", nil)
}

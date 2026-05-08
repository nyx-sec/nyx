// Phase 14 fixture (Go negative) — `url.JoinPath(base, path)` with a
// literal base anchors an origin-locked StringFact prefix that
// `is_string_safe_for_ssrf` honours, suppressing the SSRF sink at
// `http.Get` even though the path component is attacker-controlled.
package ssrf

import (
	"io"
	"net/http"
	"net/url"
)

func proxy(r *http.Request) (string, error) {
	path := r.URL.Query().Get("path")
	target, err := url.JoinPath("https://api.example.com", path)
	if err != nil {
		return "", err
	}
	resp, err := http.Get(target)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

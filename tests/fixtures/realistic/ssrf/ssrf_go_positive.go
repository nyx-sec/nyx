// Phase 14 fixture (Go positive) — attacker-controlled URL flows
// directly into `http.Get`. The query-string source taints the
// `target` value, which reaches the `http.Get` SSRF gate at arg 0.
package ssrf

import (
	"io"
	"net/http"
)

func proxy(r *http.Request) (string, error) {
	target := r.URL.Query().Get("url")
	resp, err := http.Get(target)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

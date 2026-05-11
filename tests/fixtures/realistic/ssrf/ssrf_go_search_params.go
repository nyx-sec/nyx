// Phase 14 fixture (Go search-params positive) — attacker-controlled
// URL passed positionally to `http.NewRequest(method, url, body)`. The
// SSRF gate fires on the URL at arg 1.
package ssrf

import (
	"net/http"
)

func proxy(r *http.Request, client *http.Client) (*http.Response, error) {
	target := r.URL.Query().Get("target")
	httpReq, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err
	}
	q := httpReq.URL.Query()
	q.Set("k", "v")
	httpReq.URL.RawQuery = q.Encode()
	return client.Do(httpReq)
}

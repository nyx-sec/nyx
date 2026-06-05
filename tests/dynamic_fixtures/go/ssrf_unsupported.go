// SSRF — unsupported fixture.
// Entry is a method on a struct; test sets confidence = Low.
// Expected verdict: Unsupported

package entry

import (
	"io"
	"net/http"
)

type HTTPClient struct{}

func (c *HTTPClient) Fetch(targetURL string) {
	resp, err := http.Get(targetURL)
	if err == nil {
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
	}
}

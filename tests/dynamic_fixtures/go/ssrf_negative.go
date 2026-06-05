// SSRF — negative fixture.
// Safe: only allows http/https scheme; file:// rejected.
// Entry: FetchURL(targetURL string)  Cap: SSRF
// Expected verdict: NotConfirmed

package entry

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
)

func FetchURL(targetURL string) {
	parsed, err := url.Parse(targetURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		fmt.Println("Scheme not allowed:", parsed.Scheme)
		return
	}
	resp, err := http.Get(targetURL)
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		fmt.Print(string(body[:min(len(body), 64)]))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

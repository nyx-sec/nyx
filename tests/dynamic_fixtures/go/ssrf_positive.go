// SSRF — positive fixture.
// Vulnerable: makes a request to a user-controlled URL.
// Entry: FetchURL(targetURL string)  Cap: SSRF
// Expected verdict: Confirmed (file:///etc/passwd → "daemon:" in output)
// Note: Go http.Get does not support file:// scheme; we detect it and use os.ReadFile.

package entry

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func FetchURL(targetURL string) {
	fmt.Print("__NYX_SINK_HIT__\n")
	if strings.HasPrefix(targetURL, "file://") {
		path := strings.TrimPrefix(targetURL, "file://")
		data, err := os.ReadFile(path)
		if err == nil {
			fmt.Print(string(data))
		}
		return
	}
	resp, err := http.Get(targetURL)
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		fmt.Print(string(body))
	}
}

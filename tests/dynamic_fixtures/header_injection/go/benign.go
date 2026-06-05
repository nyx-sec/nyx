// Phase 08 (Track J.6) — Go HEADER_INJECTION benign control fixture.
//
// Same shape as `vuln.go` but URL-encodes the value via
// `net/url.QueryEscape` before the header set, so CRLF bytes land as
// `%0D%0A` and the wire keeps a single header.
package benign

import (
	"net/http"
	"net/url"
)

func Run(w http.ResponseWriter, value string) {
	w.Header().Set("Set-Cookie", url.QueryEscape(value))
}

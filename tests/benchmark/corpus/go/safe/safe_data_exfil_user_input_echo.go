// DATA_EXFIL safe: plain attacker-controlled user input forwarded to a
// fixed-destination http.Post body must not fire. Sensitivity-gate
// strips the cap because the source is Plain-tier user input.
package fixture

import (
	"net/http"
	"strings"
)

func forwardUserInput(r *http.Request) {
	msg := r.FormValue("msg")
	body := strings.NewReader(msg)
	http.Post("https://analytics.internal/track", "text/plain", body)
}

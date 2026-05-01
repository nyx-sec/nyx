// DATA_EXFIL silenced regression fixture: plain user input echoed into
// the body of an outbound `http.Post` to a fixed URL must NOT fire
// `Cap::DATA_EXFIL`.  The user already controls `r.FormValue("msg")`, so
// surfacing it back into the request payload is not a cross-boundary
// disclosure.  Source-sensitivity gating in `ast.rs` strips the cap.
//
// Driven by `data_exfil_go_integration_tests.rs`.
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

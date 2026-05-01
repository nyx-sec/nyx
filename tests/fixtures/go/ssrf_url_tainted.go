// SSRF regression fixture: attacker-controlled destination URL flows
// into `http.NewRequest`'s URL position (arg 1).  SSRF must fire on the
// URL flow; DATA_EXFIL must NOT fire (the body is hardcoded `nil`).
// Cap attribution is per-position so a tainted URL never surfaces as
// data exfiltration.
//
// Driven by `data_exfil_go_integration_tests.rs`.
package fixture

import (
	"net/http"
)

func proxy(r *http.Request) {
	target := r.URL.Query().Get("target")
	req, _ := http.NewRequest("GET", target, nil)
	http.DefaultClient.Do(req)
}

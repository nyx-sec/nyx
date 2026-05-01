// Tainted URL, hardcoded body: SSRF must fire on the URL flow.  The
// query param is a `Plain` user-input source, so even though it carries
// `Cap::all()` upstream the source-sensitivity gate strips DATA_EXFIL
// for plain inputs.  Only SSRF survives.
package fixture

import (
	"net/http"
	"strings"
)

func ProxyTarget(r *http.Request) {
	target := r.URL.Query().Get("target")
	body := strings.NewReader("hardcoded")
	Forward(target, body)
}

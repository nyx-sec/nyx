// Wrapper whose two parameters target distinct gated-sink classes on the
// inner call: `url` is the SSRF gate's destination at `http.Post`'s
// arg 0; `body` is the DATA_EXFIL gate's payload at arg 2.  Pass-1 SSA
// summary extraction lifts the per-position cap split into
// `param_to_gate_filters` so cross-file callers attribute SSRF vs
// DATA_EXFIL per argument.
package fixture

import (
	"io"
	"net/http"
)

func Forward(url string, body io.Reader) {
	http.Post(url, "text/plain", body)
}

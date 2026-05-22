// Go JSON_PARSE depth-bomb vuln fixture.
//
// Models a config-driven JSON ingest endpoint that picks the parser
// input based on the request payload tag - `*_DEEP` routes through a
// deeply-nested array literal (256 levels) that drives
// `encoding/json.Unmarshal` past the 64-level depth budget;
// `*_SHALLOW` routes through a flat `[]` parse that leaves the
// predicate clear.  This shape is needed by the differential runner:
// the vuln-payload attempt and the benign-control attempt both load
// the same fixture, and only the payload-routed deep branch trips the
// `JsonParseExcessiveDepth` predicate.
//
// Go's encoding/json parser is iterative so the deep input does not
// panic the stdlib; the harness walks the returned interface{} to
// compute the observed depth and emits a `ProbeKind::JsonParse` record.
package vuln

import (
	"encoding/json"
	"strings"
)

func Run(value string) interface{} {
	text := value
	if strings.Contains(text, "DEEP") {
		nested := strings.Repeat("[", 256) + strings.Repeat("]", 256)
		var v interface{}
		_ = json.Unmarshal([]byte(nested), &v)
		return v
	}
	var v interface{}
	_ = json.Unmarshal([]byte("[]"), &v)
	return v
}

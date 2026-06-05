// Phase 08 (Track J.6) — Go HEADER_INJECTION vuln fixture.
//
// The function assigns the attacker-controlled `value` directly into a
// `Set-Cookie` header via `http.ResponseWriter.Header().Set`.  A
// payload carrying `\r\nSet-Cookie: nyx-injected=pwn` splits the
// single header into two on the wire.
package vuln

import "net/http"

func Run(w http.ResponseWriter, value string) {
	w.Header().Set("Set-Cookie", value)
}

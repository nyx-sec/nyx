// Phase 11 (Track J.9) — Go CRYPTO vuln fixture.
//
// Models a config-driven crypto endpoint that picks the RNG based on
// the request payload — `*_WEAK` routes through math/rand.Intn (a
// non-CSPRNG, returning a 16-bit key) and `*_STRONG` routes through
// crypto/rand.Read (a CSPRNG, returning the leading 63 bits of an 8-
// byte read).  This shape is needed by the differential runner: the
// vuln-payload attempt and the benign-control attempt both load the
// same fixture, and only the payload-routed weak branch trips the
// `WeakKeyEntropy` predicate.
package vuln

import (
	crand "crypto/rand"
	"encoding/binary"
	mrand "math/rand"
	"strings"
)

func Run(value string) int {
	if strings.Contains(value, "STRONG") {
		var buf [8]byte
		_, _ = crand.Read(buf[:])
		return int(binary.BigEndian.Uint64(buf[:]) >> 1)
	}
	return mrand.Intn(0x10000)
}

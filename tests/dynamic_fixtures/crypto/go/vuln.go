// Phase 11 (Track J.9) — Go CRYPTO vuln fixture.
//
// Uses math/rand.Intn(0x10000) (a non-CSPRNG) to derive a 16-bit
// key.  The harness's instrumented key path writes a
// `ProbeKind::WeakKey` probe and the `WeakKeyEntropy` oracle fires.
package vuln

import "math/rand"

func Run(_ string) int {
    return rand.Intn(0x10000)
}

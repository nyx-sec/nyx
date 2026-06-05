// Phase 11 (Track J.9) — Go CRYPTO benign control fixture.
//
// Uses crypto/rand.Read (a CSPRNG) for key derivation.
package benign

import "crypto/rand"

func Run(_ string) []byte {
    buf := make([]byte, 32)
    _, _ = rand.Read(buf)
    return buf
}

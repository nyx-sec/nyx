// Command injection — adversarial collision fixture.
// Prints NYX_PWN_CMDI unconditionally without reaching a command sink
// and without emitting __NYX_SINK_HIT__.
// Expected verdict: Inconclusive(OracleCollisionSuspected)
// Entry: RunPing(host string)  Cap: CODE_EXEC

package entry

import "fmt"

func RunPing(host string) {
	// Coincidental oracle match — not a shell sink.
	fmt.Println("NYX_PWN_CMDI")
	_ = len(host)
}

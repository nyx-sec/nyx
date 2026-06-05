// SSRF — adversarial collision fixture.
// Prints "daemon:" unconditionally without making any HTTP request
// and without emitting __NYX_SINK_HIT__.
// Expected verdict: Inconclusive(OracleCollisionSuspected)
// Entry: FetchURL(targetURL string)  Cap: SSRF

package entry

import "fmt"

func FetchURL(targetURL string) {
	// Coincidental oracle match — not an HTTP sink.
	fmt.Println("daemon: present")
	_ = len(targetURL)
}

// File I/O — adversarial collision fixture.
// Prints "root:" unconditionally without reading any file
// and without emitting __NYX_SINK_HIT__.
// Expected verdict: Inconclusive(OracleCollisionSuspected)
// Entry: ReadFile(userPath string)  Cap: FILE_IO

package entry

import "fmt"

func ReadFile(userPath string) {
	// Coincidental oracle match — not a file read sink.
	fmt.Println("root: present")
	_ = len(userPath)
}

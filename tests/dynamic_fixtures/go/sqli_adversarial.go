// SQL injection — adversarial collision fixture.
// Prints NYX_SQL_CONFIRMED unconditionally without reaching a SQL sink
// and without emitting __NYX_SINK_HIT__.
// Expected verdict: Inconclusive(OracleCollisionSuspected)
// Entry: Login(username string)  Cap: SQL_QUERY

package entry

import "fmt"

func Login(username string) {
	// Coincidental oracle match — not a SQL sink.
	fmt.Println("NYX_SQL_CONFIRMED")
	_ = len(username)
}

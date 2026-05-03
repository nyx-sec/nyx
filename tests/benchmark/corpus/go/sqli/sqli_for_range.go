// Synthetic regression fixture for the Go for-range taint propagation fix.
// Pins: a tainted iterable in `for _, p := range x` taints the loop binding `p`,
// so a SQL_QUERY sink reading `p` fires.  The structural invariant is in
// `src/cfg/literals.rs::def_use` Kind::For arm — Go's `range_clause` child
// is consulted when direct `left`/`right` fields are absent.
// Original gap surfaced via CVE-2026-41422 (daptin) goqu.L injection.
package main

import (
	"github.com/doug-martin/goqu/v9"
	"net/http"
)

func handler(r *http.Request, db *goqu.SelectDataset) {
	cols := r.URL.Query()["col"]
	for _, p := range cols {
		_ = goqu.L(p)
	}
}

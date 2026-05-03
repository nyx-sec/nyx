// Synthetic safe counterpart to sqli_for_range.go.
// Same for-range shape, but the loop binding is gated through an allowlist
// before reaching the sink, and the sink uses goqu.I (typed identifier
// constructor) rather than goqu.L (raw SQL literal).
package main

import (
	"github.com/doug-martin/goqu/v9"
	"net/http"
)

var allowedColumns = map[string]bool{"id": true, "name": true}

func safeHandler(r *http.Request, db *goqu.SelectDataset) {
	cols := r.URL.Query()["col"]
	for _, p := range cols {
		if !allowedColumns[p] {
			continue
		}
		_ = goqu.I(p)
	}
}

// Phase 15 negative — Go database/sql `db.QueryContext` parameterised.
// The SQL string is a literal with `$1` placeholder; the bind args
// passed positionally are constants, so no taint reaches either arg
// position.  Mirrors phase 07's safe-parameterised shape.
package main

import (
	"context"
	"database/sql"
	"net/http"
)

func lookup(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	_ = r.URL.Query().Get("name")
	rows, _ := db.QueryContext(context.Background(), "SELECT * FROM users WHERE id = $1", 1)
	_ = rows
}

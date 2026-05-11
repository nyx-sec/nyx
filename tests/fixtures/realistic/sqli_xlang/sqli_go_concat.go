// Phase 15 — Go database/sql raw-string concat SQLi positive.
// `db.Query` is a flat SQL_QUERY sink in `labels/go.rs`; the user-
// controlled `r.URL.Query().Get` flows into the SQL string via
// concatenation with no parameterisation.
package main

import (
	"database/sql"
	"net/http"
)

func lookup(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	name := r.URL.Query().Get("name")
	rows, _ := db.Query("SELECT * FROM users WHERE name = '" + name + "'")
	_ = rows
}

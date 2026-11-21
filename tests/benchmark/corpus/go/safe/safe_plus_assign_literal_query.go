// A query extended with `+=` from literals only.  The request value is
// never part of the SQL text.
package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("q")
	query := "SELECT id FROM items"
	query += " ORDER BY id LIMIT 10"
	db.Query(query)
}

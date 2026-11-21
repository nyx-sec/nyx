package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func list(w http.ResponseWriter, r *http.Request) {
	dir := r.URL.Query().Get("dir")
	if dir != "asc" && dir != "desc" {
		return
	}
	db.Query("SELECT * FROM t ORDER BY id " + dir)
}

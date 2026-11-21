package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func handler(w http.ResponseWriter, r *http.Request) {
	var q string
	switch r.URL.Query().Get("kind") {
	case "name":
		q = "SELECT * FROM users WHERE name = '" + r.URL.Query().Get("v") + "'"
	case "id":
		q = "SELECT * FROM users WHERE id = 1"
	default:
		q = "SELECT 1"
	}
	db.Query(q)
}

func main() {
	http.HandleFunc("/", handler)
}

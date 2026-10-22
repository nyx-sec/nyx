package main

import (
	"database/sql"
	"log"
	"net/http"
)

var db *sql.DB

func handler(w http.ResponseWriter, r *http.Request) {
	q := "SELECT id FROM items"
	switch r.URL.Query().Get("mode") {
	case "search":
		q = "SELECT id FROM items WHERE name = '" + r.URL.Query().Get("name") + "'"
		log.Println("search is disabled")
	case "list":
		db.Query(q)
	}
}

func main() {
	http.HandleFunc("/", handler)
}

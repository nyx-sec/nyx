package main

import (
	"net/http"
	"strings"

	"gorm.io/gorm"
)

var DB *gorm.DB

var sortable = map[string]bool{"id": true, "name": true, "created_at": true}

// The column is checked by a comma-ok lookup in a literal map and the
// direction by two equality tests, both on elements of the split slice.
func ListUsers(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Query().Get("order"), " ")
	if len(parts) != 2 {
		http.Error(w, "bad order", http.StatusBadRequest)
		return
	}
	if _, ok := sortable[parts[0]]; !ok {
		http.Error(w, "bad column", http.StatusBadRequest)
		return
	}
	if parts[1] != "asc" && parts[1] != "desc" {
		http.Error(w, "bad direction", http.StatusBadRequest)
		return
	}
	DB.Order(parts[0] + " " + parts[1])
}

package main

import (
	"net/http"
	"strings"

	"gorm.io/gorm"
)

var DB *gorm.DB

// Only the direction (second element) is restricted; the column is used raw.
func ListUsers(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Query().Get("order"), " ")
	if parts[1] != "asc" && parts[1] != "desc" {
		return
	}
	DB.Order(parts[0])
}

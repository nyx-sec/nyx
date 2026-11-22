package main

import (
	"net/http"
	"strings"

	"gorm.io/gorm"
)

var DB *gorm.DB

var sortable = map[string]bool{"id": true, "name": true}

// The check covers the first split of "order", but the slice is replaced
// before the element is used, so the check says nothing about the new value.
func ListUsers(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Query().Get("order"), " ")
	if _, ok := sortable[parts[0]]; !ok {
		return
	}
	parts = strings.Split(r.URL.Query().Get("sort"), " ")
	DB.Order(parts[0])
}

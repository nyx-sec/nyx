package main

import (
	"net/http"
	"strings"

	"gorm.io/gorm"
)

var DB *gorm.DB

var sortable = map[string]bool{"id": true, "name": true}

func ListUsers(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Query().Get("order"), " ")
	if len(parts) < 1 {
		return
	}
	if _, ok := sortable[parts[0]]; !ok {
		return
	}
	i := 0
	_ = parts[i]
	DB.Order(parts[0])
}

package main

import (
	"net/http"
	"strings"

	"gorm.io/gorm"
)

var DB *gorm.DB

var sortable = map[string]bool{"id": true, "name": true}

func fill(p []string, v string) {
	p[0] = v
}

func ListUsers(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Query().Get("order"), " ")
	if _, ok := sortable[parts[0]]; !ok {
		return
	}
	fill(parts, r.URL.Query().Get("sort"))
	DB.Order(parts[0])
}

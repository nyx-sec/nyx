package main

import (
	"net/http"
	"strings"

	"gorm.io/gorm"
)

var DB *gorm.DB

var sortable = map[string]bool{"id": true}

func Register(w http.ResponseWriter, r *http.Request) {
	sortable[r.URL.Query().Get("col")] = true
}

func ListUsers(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Query().Get("order"), " ")
	if _, ok := sortable[parts[0]]; !ok {
		return
	}
	DB.Order(parts[0])
}

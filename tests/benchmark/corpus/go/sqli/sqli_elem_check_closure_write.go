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
	set := func() {
		parts[0] = r.URL.Query().Get("sort")
	}
	if _, ok := sortable[parts[0]]; !ok {
		return
	}
	set()
	DB.Order(parts[0])
}

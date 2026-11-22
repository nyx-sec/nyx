package main

import (
	"net/http"
	"strings"

	"gorm.io/gorm"
)

var DB *gorm.DB

// The "allowlist" is filled from request keys, so being in it proves nothing.
func ListUsers(w http.ResponseWriter, r *http.Request) {
	cols := map[string]bool{}
	for _, c := range r.URL.Query()["cols"] {
		cols[c] = true
	}
	parts := strings.Split(r.URL.Query().Get("order"), " ")
	if _, ok := cols[parts[0]]; !ok {
		return
	}
	DB.Order(parts[0])
}

package main

import (
	"database/sql"
	"net/http"
	"os/exec"
)

var db *sql.DB

var allowed = map[string]bool{"ls": true, "pwd": true}
var allowedSet = map[string]struct{}{"ls": {}, "pwd": {}}
var sortCols = map[string]string{"name": "name", "created": "created_at"}

func commaOkReturn(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	if _, ok := allowed[cmd]; !ok {
		return
	}
	exec.Command("sh", "-c", cmd).Run()
}

func boolLookupReturn(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	ok := allowed[cmd]
	if !ok {
		return
	}
	exec.Command("sh", "-c", cmd).Run()
}

func structSetReturn(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	_, ok := allowedSet[cmd]
	if !ok {
		return
	}
	exec.Command("sh", "-c", cmd).Run()
}

func commaOkInside(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	if _, ok := allowed[cmd]; ok {
		exec.Command("sh", "-c", cmd).Run()
	}
}

func mappedValue(w http.ResponseWriter, r *http.Request) {
	sort := r.URL.Query().Get("sort")
	col, ok := sortCols[sort]
	if !ok {
		return
	}
	db.Query("SELECT * FROM t ORDER BY " + col)
}

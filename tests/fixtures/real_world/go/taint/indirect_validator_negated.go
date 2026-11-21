package main

import (
	"database/sql"
	"net/http"
	"os/exec"
	"strconv"
)

var db *sql.DB

// Safe: `!ok` rejects before the sink.
func safeBool(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	ok := isValidCommand(cmd)
	if !ok {
		http.Error(w, "bad", 400)
		return
	}
	exec.Command(cmd).Run()
}

// Vulnerable: the sink runs exactly when validation failed.
func vulnBool(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	ok := isValidCommand(cmd)
	if !ok {
		exec.Command(cmd).Run()
	}
}

// Safe: negated err-check still returns on parse failure.
func safeAtoi(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	_, err := strconv.Atoi(id)
	if !(err == nil) {
		http.Error(w, "bad", 400)
		return
	}
	db.Query("SELECT * FROM users WHERE id = " + id)
}

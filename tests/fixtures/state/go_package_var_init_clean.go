package main

import (
	"database/sql"
	"log"
	"os"
)

// Package-level handles opened in init() live for the whole program.
// Expected: no resource findings.

var db *sql.DB
var logFile *os.File

func init() {
	var err error
	db, err = sql.Open("postgres", os.Getenv("DSN"))
	if err != nil {
		log.Fatal(err)
	}
	logFile, err = os.OpenFile("/var/log/app.log", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	defer db.Close()
	defer logFile.Close()
}

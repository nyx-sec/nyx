package main

import (
	"database/sql"
	"os"
)

// The err branch of each acquire returns before the handle exists.
// Expected: no resource findings.

func simpleClose(p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	f.Close()
	return nil
}

func writeThenClose(p string) error {
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	if _, err := f.Write([]byte("x")); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func openFile(p string) (*os.File, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func openDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	return db, nil
}

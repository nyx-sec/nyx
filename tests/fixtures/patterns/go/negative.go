package main

import (
	"crypto/sha256"
	"database/sql"
)

func safeHash(data []byte) {
	sha256.Sum256(data)
}

func safeParamQuery(db *sql.DB, user string) {
	db.Query("SELECT * FROM users WHERE name = $1", user)
}

func safeLiteralQuery(db *sql.DB) {
	db.Query("SELECT COUNT(*) FROM users")
}

func safeStringOps() {
	x := "hello"
	_ = len(x)
}

// Not os/exec: a CLI builder and a Redis client both have a Command method.
func notExec(app *kingpin.Application, rdb *redis.Client, help string) {
	app.Command("check", help)
	rdb.Command(ctx)
}

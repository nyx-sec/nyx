package main

import (
	"os"
	"strconv"
)

// `err == nil` is a success check: the TRUE branch is the happy path and
// there is no error handler to judge.  The best-effort parse and the
// conditional close must not read as an error check that falls through.
func refreshCache(id string) int {
	limit := 10
	if n, err := strconv.Atoi(id); err == nil {
		limit = n
	}
	f, err := os.Open("/var/cache/app/index")
	if err == nil {
		defer f.Close()
	}
	os.Remove("/var/cache/app/stale")
	return limit
}

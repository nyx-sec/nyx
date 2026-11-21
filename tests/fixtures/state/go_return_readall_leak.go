package main

import (
	"io"
	"os"
)

// io.ReadAll reads f but does not close it.  Expected: state-resource-leak.
func slurp(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}

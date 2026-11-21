package main

import "os"

// The second `err != nil` is the Write error.  Its early return leaks f.
// Expected: state-resource-leak-possible.
func writeAll(p string, d []byte) error {
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	_, err = f.Write(d)
	if err != nil {
		return err
	}
	f.Close()
	return nil
}

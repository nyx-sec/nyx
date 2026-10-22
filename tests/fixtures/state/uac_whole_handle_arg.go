package main

import (
	"fmt"
	"os"
)

// Writing to the closed file itself.
func writeAfterClose(p string) error {
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	f.Close()
	fmt.Fprintf(f, "hello")
	return nil
}

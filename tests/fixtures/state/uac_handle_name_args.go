package main

import (
	"fmt"
	"os"
)

// f.Name() stays valid after Close; only the file itself is closed.
func logClosed(p string, w *os.File) error {
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	f.Close()
	fmt.Fprintf(os.Stderr, "closed %s\n", f.Name())
	msg := fmt.Sprintf("wrote %s", f.Name())
	w.Write([]byte(f.Name()))
	fmt.Println(msg)
	return nil
}

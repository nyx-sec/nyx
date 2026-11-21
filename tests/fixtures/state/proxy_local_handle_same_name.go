package main

import "os"

// `write` opens and closes a local file.  That says nothing about the
// receiver of a same-named call such as `f.Write(b)`.
func write(path string, b []byte) {
	f, _ := os.Create(path)
	f.Write(b)
	f.Close()
}

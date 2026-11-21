package main

import "os"

// The err branch returns before a handle exists; the success branch hands
// the handle to the caller.
func openLog(p string) (*os.File, error) {
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func main() {
	f, err := openLog("/tmp/app.log")
	if err != nil {
		return
	}
	defer f.Close()
}

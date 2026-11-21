package main

import (
	"bytes"
	"os"
)

func write(path string, data []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

// A bytes.Buffer is not the file opened by the sibling `write`.
func render(items []string) []byte {
	var buf bytes.Buffer
	for _, it := range items {
		buf.Write([]byte(it))
	}
	return buf.Bytes()
}

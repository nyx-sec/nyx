package main

import "os"

// Expected: no resource findings.
func collect(paths []string) []*os.File {
	var files []*os.File
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		files = append(files, f)
	}
	return files
}

func index(p string, m map[string]*os.File) {
	f, err := os.Open(p)
	if err != nil {
		return
	}
	m[p] = f
}

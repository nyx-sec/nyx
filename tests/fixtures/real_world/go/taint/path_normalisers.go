package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Vulnerable: Clean is lexical and keeps `../../x`; Join under a base does not
// stop it.
func cleanJoin(w http.ResponseWriter, r *http.Request) {
	f := r.FormValue("f")
	clean := filepath.Clean(f)
	data, _ := os.ReadFile(filepath.Join("/data", clean))
	w.Write(data)
}

// Vulnerable: Clean alone reads any absolute or relative path.
func cleanOnly(w http.ResponseWriter, r *http.Request) {
	f := r.FormValue("f")
	data, _ := os.ReadFile(filepath.Clean(f))
	w.Write(data)
}

// Safe: Clean, then a prefix check against the root.
func cleanHasPrefix(w http.ResponseWriter, r *http.Request) {
	f := r.FormValue("f")
	p := filepath.Clean("/data/" + f)
	if !strings.HasPrefix(p, "/data/") {
		return
	}
	data, _ := os.ReadFile(p)
	w.Write(data)
}

// Safe: Join cleans its result, so a prefix check on it is a containment test.
func joinHasPrefix(w http.ResponseWriter, r *http.Request) {
	f := r.FormValue("f")
	p := filepath.Join("/srv/data", f)
	if !strings.HasPrefix(p, "/srv/data/") {
		return
	}
	data, _ := os.ReadFile(p)
	w.Write(data)
}

// Safe: a rooted Clean joined under a base cannot climb out of it.
func rootedCleanJoin(w http.ResponseWriter, r *http.Request) {
	f := r.FormValue("f")
	c := filepath.Clean("/" + f)
	p := filepath.Join("/var/data", c)
	data, _ := os.ReadFile(p)
	w.Write(data)
}

// Safe: Base keeps only the final element.
func baseJoin(w http.ResponseWriter, r *http.Request) {
	f := r.FormValue("f")
	name := filepath.Base(f)
	data, _ := os.ReadFile(filepath.Join("/data", name))
	w.Write(data)
}

// Vulnerable: a rooted Clean read on its own is any absolute path.
func rootedCleanOnly(w http.ResponseWriter, r *http.Request) {
	f := r.FormValue("f")
	c := filepath.Clean("/" + f)
	data, _ := os.ReadFile(c)
	w.Write(data)
}

// Vulnerable: Join alone does not confine.
func joinOnly(w http.ResponseWriter, r *http.Request) {
	f := r.FormValue("f")
	p := filepath.Join("/data", f)
	data, _ := os.ReadFile(p)
	w.Write(data)
}

// Vulnerable: TrimPrefix drops the leading `/` again, so Clean sees a
// relative path and keeps its leading `..`.
func trimmedClean(w http.ResponseWriter, r *http.Request) {
	p := "/" + r.FormValue("f")
	c := filepath.Clean(strings.TrimPrefix(p, "/"))
	data, _ := os.ReadFile(filepath.Join("/var/data", c))
	w.Write(data)
}

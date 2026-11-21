// Safe: only numbers derived from the request reach the response header.
// strconv's integer formatters cannot emit CR/LF or header syntax.
package main

import (
	"net/http"
	"strconv"
)

func lenInline(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	w.Header().Set("X-Len", strconv.Itoa(len(q)))
}

func lenBound(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	n := len(q)
	s := strconv.Itoa(n)
	w.Header().Set("X-Len", s)
}

func lenFormatted(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	w.Header().Add("X-Len", strconv.FormatInt(int64(len(q)), 10))
}

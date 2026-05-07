// Unsafe: net/http `ResponseWriter.Header().Set` receives a value built from
// `r.URL.Query().Get`.  HEADER_INJECTION fires on the value argument.
package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	lang := r.URL.Query().Get("lang")
	w.Header().Set("X-Lang", lang)
}

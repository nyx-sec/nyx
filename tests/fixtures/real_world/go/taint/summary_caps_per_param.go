package main

import (
	"fmt"
	"net/http"
	"net/url"
)

// writeResponse's parameters reach different sink classes: body is written
// to the response (XSS), mime is a header value.  writeError passes a
// request-derived body and a constant mime, so its callers see an XSS flow
// and no header flow.
func writeResponse(w http.ResponseWriter, code int, body []byte, mime string) {
	if mime != "" {
		w.Header().Set("Content-Type", mime)
	}
	w.WriteHeader(code)
	fmt.Fprintf(w, "%s", body)
}

func writeError(w http.ResponseWriter, reqURL *url.URL) {
	writeResponse(w, 500, encode(reqURL.Path), "application/xml")
}

func Handler(w http.ResponseWriter, r *http.Request) {
	writeError(w, r.URL)
}

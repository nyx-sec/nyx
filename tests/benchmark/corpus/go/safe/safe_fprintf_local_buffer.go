package main

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
)

// Formatting request data into an in-memory buffer is not a response write.
// The buffers are declared without an initialiser and passed by address,
// the idiomatic Go shape the writer type has to be read from.
func render(r *http.Request) string {
	name := r.URL.Query().Get("name")
	var sb strings.Builder
	fmt.Fprintf(&sb, "name=%s", name)
	var buf bytes.Buffer
	fmt.Fprintln(&buf, name)
	return sb.String() + buf.String()
}

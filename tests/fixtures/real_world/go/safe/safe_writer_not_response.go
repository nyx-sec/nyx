package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func builder(w http.ResponseWriter, r *http.Request) string {
	name := r.URL.Query().Get("name")
	var sb strings.Builder
	fmt.Fprintf(&sb, "name=%s", name)
	io.WriteString(&sb, name)
	return sb.String()
}

func buffers(r *http.Request) string {
	name := r.URL.Query().Get("name")
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "name=%s", name)
	buf2 := &bytes.Buffer{}
	fmt.Fprintln(buf2, name)
	return buf.String() + buf2.String()
}

func writerFormal(out io.Writer, r *http.Request) {
	q := r.URL.Query().Get("q")
	io.WriteString(out, q)
	fmt.Fprintf(out, "row %s\n", q)
}

func jsonBody(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	b, _ := json.Marshal(map[string]string{"q": q})
	w.Write(b)
}

func logging() {
	fmt.Fprintln(os.Stderr, os.Getenv("DEBUG"))
	fmt.Fprintf(os.Stdout, "%s\n", os.Getenv("HOME"))
}

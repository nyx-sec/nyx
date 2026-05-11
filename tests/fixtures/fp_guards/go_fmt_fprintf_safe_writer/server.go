package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

// Package-level non-response writers, mirroring gin's `mode.go` declarations.
// These are `io.Writer` aliases for `os.Stdout` / `os.Stderr` and are NOT
// HTTP response sinks.
var (
	DefaultWriter      io.Writer = os.Stdout
	DefaultErrorWriter io.Writer = os.Stderr
)

// debugPrintError is the gin-style logging helper.  It writes to a
// package-level non-response writer.  When `err` returns from
// `http.Server.ListenAndServe`, the value is stdlib state, not user input,
// but the engine should still suppress HTML_ESCAPE on the writer-aware
// branch even if a tainted value reached the writer.
func debugPrintError(err error) {
	if err != nil {
		fmt.Fprintf(DefaultErrorWriter, "[debug] [ERROR] %v\n", err)
	}
}

// debugPrint writes formatted debug output to stdout-aliased DefaultWriter.
func debugPrint(format string, values ...any) {
	fmt.Fprintf(DefaultWriter, "[debug] "+format, values...)
}

// runServer mirrors gin's `Engine.Run` shape: a deferred call that pipes
// the named-return error into the gin-style debug logger.
func runServer(addr string) (err error) {
	defer func() { debugPrintError(err) }()
	server := &http.Server{Addr: addr}
	err = server.ListenAndServe()
	return
}

// stdlibLog is the equivalent shape using stdlib stderr directly.
func stdlibLog(err error) {
	fmt.Fprintf(os.Stderr, "boot error: %v\n", err)
}

// discardLog drops formatted output entirely.  Always benign.
func discardLog(payload string) {
	fmt.Fprintf(io.Discard, "ignored: %s\n", payload)
}

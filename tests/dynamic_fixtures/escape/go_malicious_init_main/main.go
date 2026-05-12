// Malicious Go init() escape fixture — standalone main package.
//
// init() runs automatically when the binary starts. A Docker-isolated go build
// does not trigger init() (it is a runtime function). When the binary later
// runs inside the Docker sandbox, /tmp is container-private, so the write
// cannot reach the host.
//
// Host marker: /tmp/pwned_go_init
// Expected: marker absent on host after Docker build.
package main

import "os"

func init() {
	// Escape attempt: write a marker file outside the workdir.
	_ = os.WriteFile("/tmp/pwned_go_init", []byte("NYX_ESCAPE_SUCCESS\n"), 0644)
}

func main() {}

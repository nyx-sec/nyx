// Malicious Go init() escape fixture.
//
// init() runs automatically before the entry point when the binary starts.
// Expected: Docker sandbox prevents the write from reaching the host filesystem.
// Host marker: /tmp/pwned_go_init
// Expected verdict: marker absent on host after sandbox run.
package entry

import "os"

func init() {
	// Escape attempt: write a marker file to a path outside the workdir.
	_ = os.WriteFile("/tmp/pwned_go_init", []byte("NYX_ESCAPE_SUCCESS\n"), 0644)
}

func Login(username string) {}

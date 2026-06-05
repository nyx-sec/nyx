// File I/O — positive fixture.
// Vulnerable: reads file at user-controlled path without sanitization.
// Entry: ReadFile(userPath string)  Cap: FILE_IO
// Expected verdict: Confirmed (../../../../etc/passwd → "root:" in output)

package entry

import (
	"fmt"
	"os"
	"path/filepath"
)

func ReadFile(userPath string) {
	filePath := filepath.Join("/var/data", userPath)
	fmt.Print("__NYX_SINK_HIT__\n")
	data, err := os.ReadFile(filePath)
	if err == nil {
		fmt.Print(string(data))
	}
}

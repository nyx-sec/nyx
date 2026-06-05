// File I/O — negative fixture.
// Safe: path is resolved and validated against base directory.
// Entry: ReadFile(userPath string)  Cap: FILE_IO
// Expected verdict: NotConfirmed

package entry

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const baseDir = "/var/data"

func ReadFile(userPath string) {
	resolved, err := filepath.Abs(filepath.Join(baseDir, userPath))
	if err != nil || !strings.HasPrefix(resolved, baseDir+string(filepath.Separator)) {
		fmt.Println("Access denied")
		return
	}
	data, err := os.ReadFile(resolved)
	if err == nil {
		fmt.Print(string(data[:min(len(data), 100)]))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

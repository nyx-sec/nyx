// Phase 15 — fuzz-style variadic harness, benign.
// Validates input length then echoes a fixed string.

package entry

import (
	"fmt"
	"os/exec"
)

func FuzzHandle(data []byte) error {
	if len(data) > 1024 {
		return fmt.Errorf("too long")
	}
	cmd := exec.Command("echo", "hello")
	out, _ := cmd.CombinedOutput()
	fmt.Print(string(out))
	return nil
}

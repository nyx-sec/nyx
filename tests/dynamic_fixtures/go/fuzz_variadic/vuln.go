// Phase 15 — fuzz-style variadic harness, vulnerable.
// Takes raw bytes and pipes to /bin/sh -c.
// Entry: FuzzHandle(data []byte) error  Cap: CODE_EXEC

package entry

import (
	"fmt"
	"os/exec"
)

func FuzzHandle(data []byte) error {
	fmt.Print("__NYX_SINK_HIT__\n")
	cmd := exec.Command("sh", "-c", "echo hello "+string(data))
	out, _ := cmd.CombinedOutput()
	fmt.Print(string(out))
	return nil
}

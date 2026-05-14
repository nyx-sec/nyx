// Phase 15 — flag.Parse CLI, benign.
// Echoes a fixed string; argv is discarded.

package entry

import (
	"flag"
	"fmt"
	"os/exec"
)

func Run() {
	flag.Parse()
	_ = flag.Args()
	cmd := exec.Command("echo", "hello")
	out, _ := cmd.CombinedOutput()
	fmt.Print(string(out))
}

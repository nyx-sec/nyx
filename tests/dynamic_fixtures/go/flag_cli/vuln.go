// Phase 15 — flag.Parse CLI, vulnerable.
// Reads the first non-flag argv positional and pipes to /bin/sh -c.
// Entry: Run()  Cap: CODE_EXEC

package entry

import (
	"flag"
	"fmt"
	"os/exec"
)

func Run() {
	fmt.Print("__NYX_SINK_HIT__\n")
	flag.Parse()
	payload := ""
	if flag.NArg() > 0 {
		payload = flag.Arg(0)
	}
	cmd := exec.Command("sh", "-c", "echo hello "+payload)
	out, _ := cmd.CombinedOutput()
	fmt.Print(string(out))
}

// Command injection — negative fixture.
// Safe: passes host as a separate arg to exec.Command (no shell invoked).
// Entry: RunPing(host string)  Cap: CODE_EXEC
// Expected verdict: NotConfirmed

package entry

import (
	"fmt"
	"os/exec"
)

func RunPing(host string) {
	// exec.Command does not invoke a shell; host is a literal argument.
	cmd := exec.Command("echo", "hello", host)
	out, _ := cmd.CombinedOutput()
	fmt.Print(string(out))
}

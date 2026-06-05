// Command injection — positive fixture.
// Vulnerable: passes user input to /bin/sh -c.
// Entry: RunPing(host string)  Cap: CODE_EXEC
// Expected verdict: Confirmed ("; echo NYX_PWN_CMDI" echoes the marker)

package entry

import (
	"fmt"
	"os/exec"
)

func RunPing(host string) {
	fmt.Print("__NYX_SINK_HIT__\n")
	cmd := exec.Command("/bin/sh", "-c", "/bin/echo hello "+host)
	out, _ := cmd.CombinedOutput()
	fmt.Print(string(out))
}

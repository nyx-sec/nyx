// Command injection — unsupported fixture.
// Entry is a method on a struct.
// Test sets confidence = Low to get Unsupported(ConfidenceTooLow).
// Entry: Runner.Execute  Cap: CODE_EXEC
// Expected verdict: Unsupported

package entry

import "os/exec"

type Runner struct{}

func (r *Runner) Execute(cmd string) {
	exec.Command("sh", "-c", cmd).Run()
}

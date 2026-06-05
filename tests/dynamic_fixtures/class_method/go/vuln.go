// Phase 19 (Track M.1) — class-method vuln fixture for Go.
//
// UserService.Run accepts user input and passes it to `sh -c` so the
// shell interprets it.  The harness compiles in a generated
// `nyx_auto_registry.go` that publishes `UserService{}` so reflection
// works without a hand-rolled registry in the fixture.
package entry

import "os/exec"

type UserService struct{}

func (UserService) Run(input string) string {
	// SINK: tainted input → shell -c
	out, _ := exec.Command("sh", "-c", "true "+input).Output()
	return string(out)
}

// Phase 19 (Track M.1) — class-method vuln fixture for Go.
//
// UserService.Run accepts user input and passes it to `sh -c` so the
// shell interprets it.  The fixture publishes its instance through the
// well-known `NyxReceivers` registry the harness uses to construct
// receivers reflectively.
package entry

import "os/exec"

type UserService struct{}

func (UserService) Run(input string) string {
	// SINK: tainted input → shell -c
	out, _ := exec.Command("sh", "-c", "echo "+input).Output()
	return string(out)
}

var NyxReceivers = map[string]interface{}{
	"UserService": UserService{},
}

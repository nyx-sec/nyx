// Class-method fixture with recursively populated Go struct dependencies.
package entry

import "os/exec"

type ShellRunner struct{}

func (ShellRunner) Run(command string) string {
	out, _ := exec.Command("sh", "-c", "true "+command).Output()
	return string(out)
}

type UserRepository struct {
	Runner *ShellRunner
}

func (r UserRepository) Find(input string) string {
	if r.Runner == nil {
		return ""
	}
	return r.Runner.Run(input)
}

type UserService struct {
	Repository *UserRepository
}

func (s UserService) Run(input string) string {
	if s.Repository == nil {
		return ""
	}
	return s.Repository.Find(input)
}

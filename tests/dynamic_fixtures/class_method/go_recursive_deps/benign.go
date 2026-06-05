// Benign control for recursively populated Go struct dependencies.
package entry

import "strings"

type ShellRunner struct{}

func (ShellRunner) Run(command string) string {
	return strings.ReplaceAll(command, "NYX_PWN", "")
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

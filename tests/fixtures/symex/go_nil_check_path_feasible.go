package main

import (
	"os"
	"os/exec"
	"strings"
)

// `err` and `command` are only known by their static types, so either can
// be nil.  Both sinks sit behind a nil check and must stay reachable.
func run() error {
	cmd := os.Getenv("SSH_ORIGINAL_COMMAND")
	fields := strings.Split(cmd, " ")
	verb := fields[0]

	var command *exec.Cmd
	if _, err := os.Stat("/usr/bin/" + verb); err != nil {
		command = exec.Command("git", verb)
	}
	if command == nil {
		command = exec.Command(verb)
	}
	return command.Run()
}

func main() {
	_ = run()
}

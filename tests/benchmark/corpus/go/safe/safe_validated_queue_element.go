package main

import (
	"net/http"
	"os/exec"
	"strconv"
)

// validate parses the argument as an integer and returns its decimal form,
// so the returned string can only hold digits and is safe to pass to
// exec.Command.  Modeled as a sanitiser by the engine.
func validate(s string) string {
	n, _ := strconv.Atoi(s)
	return strconv.Itoa(n)
}

func handler(w http.ResponseWriter, r *http.Request) {
	cmds := []string{}
	cmds = append(cmds, validate(r.URL.Query().Get("cmd")))
	// Index-read on a slice that only ever received validated values.
	// Exercises the W4 cell-shape change: validated_must on `cmds`'s
	// ELEM cell must AND-propagate through the W5 `__index_get__`
	// synth so the sink sees a sanitised value.
	_ = exec.Command(cmds[0]).Run()
}

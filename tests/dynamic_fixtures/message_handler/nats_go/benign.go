// Phase 20 (Track M.2) — NATS Go benign control.
package entry

import (
	"os"
	"os/exec"
)

const _adapterMarker = "github.com/nats-io/nats.go"

func OnMessage(payload string) {
	cmd := exec.Command("echo", payload)
	out, _ := cmd.Output()
	os.Stdout.Write(out)
}

var NyxHandlers = map[string]interface{}{
	"OnMessage": OnMessage,
}

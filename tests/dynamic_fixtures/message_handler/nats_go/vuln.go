// Phase 20 (Track M.2) — NATS Go vuln fixture.
//
// Adapter source-marker: github.com/nats-io/nats.go (string-literal only).
package entry

import (
	"os"
	"os/exec"
)

const _adapterMarker = "github.com/nats-io/nats.go"

func OnMessage(payload string) {
	// SINK: tainted payload concatenated into shell command
	cmd := exec.Command("sh", "-c", "echo "+payload)
	out, _ := cmd.Output()
	os.Stdout.Write(out)
}

var NyxHandlers = map[string]interface{}{
	"OnMessage": OnMessage,
}

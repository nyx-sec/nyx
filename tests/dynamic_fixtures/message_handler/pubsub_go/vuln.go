// Phase 20 (Track M.2) — Google Pub/Sub Go vuln fixture.
//
// Adapter source-marker: cloud.google.com/go/pubsub (string-literal only).
// The handler signature accepts a string so the Phase 20 harness
// dispatch falls through to the NYX_PAYLOAD env var.
package entry

import (
	"os"
	"os/exec"
)

const _adapterMarker = "cloud.google.com/go/pubsub"

func OnMessage(payload string) {
	// SINK: tainted payload concatenated into shell command
	cmd := exec.Command("sh", "-c", "echo "+payload)
	out, _ := cmd.Output()
	os.Stdout.Write(out)
}

var NyxHandlers = map[string]interface{}{
	"OnMessage": OnMessage,
}

// Phase 20 (Track M.2) — Google Pub/Sub Go benign control.
package entry

import (
	"os"
	"os/exec"
)

const _adapterMarker = "cloud.google.com/go/pubsub"

func OnMessage(payload string) {
	cmd := exec.Command("echo", payload)
	out, _ := cmd.Output()
	os.Stdout.Write(out)
}

var NyxHandlers = map[string]interface{}{
	"OnMessage": OnMessage,
}

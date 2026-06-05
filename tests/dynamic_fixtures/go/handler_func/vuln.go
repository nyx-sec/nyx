// Phase 15 — http.HandlerFunc, vulnerable.
// Reads `?payload=` query value and pipes to /bin/sh -c.
// Entry: Handle(w http.ResponseWriter, r *http.Request)  Cap: CODE_EXEC

package entry

import (
	"fmt"
	"net/http"
	"os/exec"
)

func Handle(w http.ResponseWriter, r *http.Request) {
	fmt.Print("__NYX_SINK_HIT__\n")
	payload := r.URL.Query().Get("payload")
	cmd := exec.Command("sh", "-c", "echo hello "+payload)
	out, _ := cmd.CombinedOutput()
	fmt.Print(string(out))
	w.WriteHeader(http.StatusOK)
	w.Write(out)
}

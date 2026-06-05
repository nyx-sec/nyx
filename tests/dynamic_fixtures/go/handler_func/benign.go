// Phase 15 — http.HandlerFunc, benign.
// Echoes a fixed string; query value is discarded.

package entry

import (
	"fmt"
	"net/http"
	"os/exec"
)

func Handle(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("payload")
	cmd := exec.Command("echo", "hello")
	out, _ := cmd.CombinedOutput()
	fmt.Print(string(out))
	w.WriteHeader(http.StatusOK)
	w.Write(out)
}

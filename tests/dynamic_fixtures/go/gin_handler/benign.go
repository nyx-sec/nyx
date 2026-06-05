// Phase 15 — gin handler, benign.
// Echoes a fixed string; query value is discarded.

package entry

import (
	"fmt"
	"os/exec"

	"nyx-harness/entry/gin"
)

func Handle(c *gin.Context) {
	_ = c.Query("payload")
	cmd := exec.Command("echo", "hello")
	out, _ := cmd.CombinedOutput()
	fmt.Print(string(out))
	c.String(200, "%s", string(out))
}

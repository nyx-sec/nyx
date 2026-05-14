// Phase 15 — gin handler, vulnerable.
// Reads gin context query value and pipes to /bin/sh -c.
// Entry: Handle(c *gin.Context)  Cap: CODE_EXEC

package entry

import (
	"fmt"
	"os/exec"

	"nyx-harness/entry/gin"
)

func Handle(c *gin.Context) {
	fmt.Print("__NYX_SINK_HIT__\n")
	payload := c.Query("payload")
	cmd := exec.Command("sh", "-c", "echo hello "+payload)
	out, _ := cmd.CombinedOutput()
	fmt.Print(string(out))
	c.String(200, "%s", string(out))
}

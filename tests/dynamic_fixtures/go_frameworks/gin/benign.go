// Phase 17 (Track L.15) — gin benign control fixture.
//
// The /run route accepts a `cmd` query parameter but only runs an
// allow-listed command, so the sink never sees attacker-controlled
// bytes.  Same adapter binding as the vuln fixture.
package main

import (
	"os/exec"

	"github.com/gin-gonic/gin"
)

func Run(c *gin.Context) {
	cmd := c.Query("cmd")
	allow := map[string]string{"ls": "ls", "ps": "ps"}
	if safe, ok := allow[cmd]; ok {
		_ = exec.Command(safe).Run()
	}
}

func main() {
	r := gin.Default()
	r.GET("/run", Run)
	_ = r
}

// Phase 17 (Track L.15) — gin CMDI vuln fixture.
//
// The /run route forwards a `cmd` query parameter straight into
// `os/exec.Command`, so any attacker who reaches the route can
// execute arbitrary shell.  Adapter binding: `r.GET("/run", Run)`
// with `cmd` flowing through `c.Query`.
package main

import (
	"fmt"
	"os/exec"

	"github.com/gin-gonic/gin"
)

func Run(c *gin.Context) {
	cmd := c.Query("cmd")
	fmt.Print("__NYX_SINK_HIT__\n")
	out, _ := exec.Command("sh", "-c", cmd).CombinedOutput()
	fmt.Print(string(out))
}

func main() {
	r := gin.Default()
	r.GET("/run", Run)
	_ = r
}

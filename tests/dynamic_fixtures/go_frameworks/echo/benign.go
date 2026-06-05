// Phase 17 (Track L.15) — echo benign control fixture.
//
// The /run route consults an allow-list before invoking exec, so
// attacker bytes never reach the sink directly.
package main

import (
	"os/exec"

	"github.com/labstack/echo/v4"
)

func Run(c echo.Context) error {
	cmd := c.QueryParam("cmd")
	allow := map[string]string{"ls": "ls", "ps": "ps"}
	if safe, ok := allow[cmd]; ok {
		return exec.Command(safe).Run()
	}
	return nil
}

func main() {
	e := echo.New()
	e.GET("/run", Run)
	_ = e
}

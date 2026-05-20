// Phase 17 (Track L.15) — echo CMDI vuln fixture.
//
// The /run route forwards a `cmd` query parameter straight into
// `os/exec.Command`.  Adapter binding: `e.GET("/run", Run)` with
// `cmd` flowing through `c.QueryParam`.
package main

import (
	"os/exec"

	"github.com/labstack/echo/v4"
)

func Run(c echo.Context) error {
	cmd := c.QueryParam("cmd")
	return exec.Command("sh", "-c", cmd).Run()
}

func main() {
	e := echo.New()
	e.GET("/run", Run)
	_ = e
}

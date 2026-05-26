// Phase 17 (Track L.15) — echo CMDI vuln fixture.
//
// The /run route forwards a `cmd` query parameter straight into
// `os/exec.Command`.  Adapter binding: `e.GET("/run", Run)` with
// `cmd` flowing through `c.QueryParam`.
package main

import (
	"fmt"
	"os/exec"

	"github.com/labstack/echo/v4"
)

func Run(c echo.Context) error {
	cmd := c.QueryParam("cmd")
	fmt.Print("__NYX_SINK_HIT__\n")
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	fmt.Print(string(out))
	return err
}

func main() {
	e := echo.New()
	e.GET("/run", Run)
	_ = e
}

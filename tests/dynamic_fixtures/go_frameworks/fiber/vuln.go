// Phase 17 (Track L.15) — fiber CMDI vuln fixture.
//
// The /run route forwards a `cmd` query parameter straight into
// `os/exec.Command`.  Adapter binding: `app.Get("/run", Run)` with
// `cmd` flowing through `c.Query`.
package main

import (
	"fmt"
	"os/exec"

	"github.com/gofiber/fiber/v2"
)

func Run(c *fiber.Ctx) error {
	cmd := c.Query("cmd")
	fmt.Print("__NYX_SINK_HIT__\n")
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	fmt.Print(string(out))
	return err
}

func main() {
	app := fiber.New()
	app.Get("/run", Run)
	_ = app
}

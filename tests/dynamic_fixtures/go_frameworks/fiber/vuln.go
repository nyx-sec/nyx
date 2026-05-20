// Phase 17 (Track L.15) — fiber CMDI vuln fixture.
//
// The /run route forwards a `cmd` query parameter straight into
// `os/exec.Command`.  Adapter binding: `app.Get("/run", Run)` with
// `cmd` flowing through `c.Query`.
package main

import (
	"os/exec"

	"github.com/gofiber/fiber/v2"
)

func Run(c *fiber.Ctx) error {
	cmd := c.Query("cmd")
	return exec.Command("sh", "-c", cmd).Run()
}

func main() {
	app := fiber.New()
	app.Get("/run", Run)
	_ = app
}

// Phase 17 (Track L.15) — fiber benign control fixture.
package main

import (
	"os/exec"

	"github.com/gofiber/fiber/v2"
)

func Run(c *fiber.Ctx) error {
	cmd := c.Query("cmd")
	allow := map[string]string{"ls": "ls", "ps": "ps"}
	if safe, ok := allow[cmd]; ok {
		return exec.Command(safe).Run()
	}
	return nil
}

func main() {
	app := fiber.New()
	app.Get("/run", Run)
	_ = app
}

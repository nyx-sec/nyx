package main

import (
	"context"
	"net/http"
	"os/exec"
)

func gitStatus(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "git", "status", "--porcelain")
	return cmd.Run()
}

func gitContinue(ctx context.Context) error {
	_, err := exec.CommandContext(ctx, "git", "cherry-pick", "--continue").Output()
	return err
}

func list(w http.ResponseWriter, r *http.Request) {
	exec.CommandContext(r.Context(), "ls", "-la").Run()
}

func index(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "/srv/static/index.html")
}

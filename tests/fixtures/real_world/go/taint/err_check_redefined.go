package main

import (
	"net/http"
	"os"
	"os/exec"
)

func reused(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	_, err := os.Getwd()
	if err != nil {
		return
	}
	_, err = os.Stat("/srv/" + "data")
	if err != nil {
		exec.Command("sh", "-c", "echo "+name).Run()
	}
}

func opposite(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	_, err := os.Stat("/srv/data")
	if err == nil {
		return
	}
	if err != nil {
		exec.Command("sh", "-c", "echo "+name).Run()
	}
}

func repeated(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	_, err := os.Stat("/srv/data")
	if err != nil {
		return
	}
	if err != nil {
		exec.Command("sh", "-c", "echo "+name).Run()
	}
}

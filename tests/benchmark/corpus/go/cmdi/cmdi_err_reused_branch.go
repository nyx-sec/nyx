package main

import (
	"net/http"
	"os"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	_, err := os.Getwd()
	if err != nil {
		return
	}
	_, err = os.Stat("/srv/cache")
	if err != nil {
		exec.Command("sh", "-c", "mkdir /srv/cache/"+name).Run()
	}
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8080", nil)
}

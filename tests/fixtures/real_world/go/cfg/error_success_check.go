package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
)

func bestEffortParse(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	if n, err := strconv.Atoi(id); err == nil {
		_ = n
	}
	os.Remove("/tmp/cache")
}

func bestEffortClose() {
	f, err := os.Open("/tmp/x")
	if nil == err {
		defer f.Close()
	}
	os.Remove("/tmp/cache")
}

func elseReturns(input string) {
	_, err := strconv.Atoi(input)
	if err == nil {
		fmt.Println("ok")
	} else {
		return
	}
	exec.Command("sh", "-c", input).Run()
}

func elseFallsThrough(input string) {
	_, err := strconv.Atoi(input)
	if err == nil {
		fmt.Println("ok")
	} else {
		fmt.Println("warn")
	}
	exec.Command("sh", "-c", input).Run()
}

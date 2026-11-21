package main

import (
	"io"
	"net/http"
	"os"
	"os/exec"
)

// The request formal is recognised by its declared type, not its name.
func readByReq(w http.ResponseWriter, req *http.Request) {
	name := req.FormValue("name")
	os.ReadFile(name)
}

func runByHeader(w http.ResponseWriter, httpReq *http.Request) {
	cmd := httpReq.Header.Get("X-Cmd")
	exec.Command(cmd).Run()
}

func runByQuery(w http.ResponseWriter, in *http.Request) {
	arg := in.URL.Query().Get("arg")
	exec.Command("sh", "-c", arg).Run()
}

func runByBody(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	exec.Command(string(b)).Run()
}

// Accessors that had no rule under any receiver name.
func readByPathValue(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	os.ReadFile("/srv/" + id)
}

func readByForm(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	a := r.Form.Get("a")
	os.ReadFile(a)
	b := r.PostFormValue("b")
	os.ReadFile(b)
}

// A closure sees the enclosing handler's request formal.
func readInClosure(w http.ResponseWriter, req *http.Request) {
	done := make(chan bool)
	go func() {
		os.ReadFile(req.FormValue("f"))
		done <- true
	}()
	<-done
}

func main() {
	http.HandleFunc("/a", readByReq)
	http.HandleFunc("/b", runByHeader)
	http.HandleFunc("/c", runByQuery)
	http.HandleFunc("/d", runByBody)
	http.HandleFunc("/e", readByPathValue)
	http.HandleFunc("/f", readByForm)
	http.HandleFunc("/g", readInClosure)
	http.ListenAndServe(":8080", nil)
}

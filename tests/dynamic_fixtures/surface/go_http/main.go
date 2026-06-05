package main

import "net/http"

func main() {
	http.HandleFunc("/users", listUsers)
	http.ListenAndServe(":8080", nil)
}

func listUsers(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("[]"))
}

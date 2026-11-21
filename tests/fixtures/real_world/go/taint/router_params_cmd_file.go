package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
)

var db *sql.DB

func muxVars(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	db.QueryRow(fmt.Sprintf("SELECT name FROM users WHERE id = %s", id))
}

func chiParam(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	exec.Command("sh", "-c", "echo "+name).Run()
}

func commandContext(w http.ResponseWriter, r *http.Request) {
	cmd := exec.CommandContext(r.Context(), "sh", "-c", r.FormValue("c"))
	cmd.Run()
}

func serveFile(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("f")
	http.ServeFile(w, r, filepath.Join("/srv/static", name))
}

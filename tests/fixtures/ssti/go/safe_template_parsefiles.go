// Safe-template-var: html/template loaded from disk via `ParseFiles`
// (path-traversal class, not SSTI).  User input reaches the data arg of
// Execute but the template body is constant.

package ssti

import (
	"net/http"

	"html/template"
)

func HandlerParseFiles(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	tpl := template.Must(template.ParseFiles("greeting.tmpl"))
	tpl.Execute(w, struct{ Name string }{Name: name})
}

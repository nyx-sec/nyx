// Safe: text/template parsed from a constant source string; user input
// flows into the data argument of `Execute`, which is rendered via the
// template's escape policy (not as source).

package ssti

import (
	"net/http"
	"text/template"
)

func HandlerSafe(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	tpl, err := template.New("x").Parse("Hello, {{.Name}}")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	tpl.Execute(w, struct{ Name string }{Name: name})
}

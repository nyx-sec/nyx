// Unsafe: text/template `template.New("x").Parse(src)` where src is
// taken from a request query parameter.  Tainted template source =
// SSTI; html/template's auto-escaping applies during Execute, not Parse,
// so a tainted source still yields template injection.

package ssti

import (
	"net/http"
	"text/template"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	src := r.URL.Query().Get("template")
	tpl, err := template.New("x").Parse(src)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	tpl.Execute(w, nil)
}

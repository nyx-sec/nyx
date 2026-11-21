// net/http handler whose request formal is named `r`, the standard Go
// convention.  The `*http.Request` declared type is the user-input evidence,
// not the binding name.  Pinned in
// `auth_analysis_tests::go_request_typed_param_opens_ownership_rule`.
package api

import (
	"net/http"

	"example.com/store"
	"github.com/gorilla/mux"
)

func DeleteDocument(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	docID := vars["id"]
	store.DB.DeleteDocument(docID)
	w.WriteHeader(204)
}

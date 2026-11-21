// Recall guard for `go_package_symbols_clean.go`: a parameter or local that
// shares a name with an import or a file const is a value, so the id-shaped
// field on it is still a subject.  Pinned in `auth_analysis_tests`.
package harbor

import "example.com/event"

const userID = "fixed"

func Handle(req *http.Request, event *Event) {
	store.DB.DeleteEvent(event.ID)
}

func Handler(w http.ResponseWriter, r *http.Request) {
	userID := r.FormValue("userID")
	store.DB.DeleteUser(userID)
}

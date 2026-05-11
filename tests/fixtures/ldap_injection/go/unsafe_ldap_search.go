// Unsafe: form value concatenated into an LDAP filter passed to
// ldap.NewSearchRequest, then executed via conn.Search.  The construction
// call is tagged Cap::LDAP_INJECTION on the filter argument so the finding
// fires here regardless of the eventual conn.Search execution site.
package ldap_unsafe

import (
	"fmt"
	"net/http"

	"github.com/go-ldap/ldap/v3"
)

func Lookup(w http.ResponseWriter, r *http.Request) {
	conn, _ := ldap.DialURL("ldap://example.com")
	user := r.FormValue("user")
	filter := fmt.Sprintf("(uid=%s)", user)
	req := ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{"cn"},
		nil,
	)
	conn.Search(req)
}

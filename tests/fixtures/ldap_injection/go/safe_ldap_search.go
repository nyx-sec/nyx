// Safe: ldap.EscapeFilter applies RFC 4515 escaping before the user value
// is interpolated into the filter.  Sanitizer(LDAP_INJECTION) clears the cap.
package ldap_safe

import (
	"fmt"
	"net/http"

	"github.com/go-ldap/ldap/v3"
)

func Lookup(w http.ResponseWriter, r *http.Request) {
	conn, _ := ldap.DialURL("ldap://example.com")
	user := r.FormValue("user")
	safe := ldap.EscapeFilter(user)
	filter := fmt.Sprintf("(uid=%s)", safe)
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

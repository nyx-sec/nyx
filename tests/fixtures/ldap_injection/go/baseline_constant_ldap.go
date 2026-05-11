// Baseline: filter is a literal string, no taint reaches NewSearchRequest.
package ldap_baseline

import (
	"github.com/go-ldap/ldap/v3"
)

func Lookup() {
	conn, _ := ldap.DialURL("ldap://example.com")
	req := ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=person)",
		[]string{"cn"},
		nil,
	)
	conn.Search(req)
}

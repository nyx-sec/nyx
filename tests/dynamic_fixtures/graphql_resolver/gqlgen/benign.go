// Phase 21 — gqlgen benign control.
package benign

// import "github.com/99designs/gqlgen/graphql"

import "regexp"

var idAllow = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func ResolveUser(id string) (string, error) {
	if !idAllow.MatchString(id) {
		return "", nil
	}
	return "user-" + id, nil
}

// Phase 21 (Track M.3) — gqlgen GraphQL resolver vuln fixture.
//
// `resolveUser(ctx, id)` is a gqlgen resolver (substring marker only —
// the real gqlgen runtime is not on the workdir's go.mod).  The
// resolver splices the id into a shell command via os/exec.
package vuln

// import "github.com/99designs/gqlgen/graphql"

import (
	"os/exec"
)

// type queryResolver struct{}

func ResolveUser(id string) (string, error) {
	// SINK: tainted id concatenated into shell command.
	out, err := exec.Command("/bin/sh", "-c", "echo lookup-"+id).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

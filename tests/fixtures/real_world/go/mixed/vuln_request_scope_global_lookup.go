package repo

import (
	"example.com/models/repo"
	"example.com/services/context"
)

// Recall guard for safe_request_scope_receiver.go: a lookup by the request id
// through a package function is not confined to the authorised repository.
func ShowAny(ctx *context.Context) {
	id := ctx.PathParam("id")
	r, err := repo.GetRepositoryByID(ctx, id)
	_, _ = r, err
}

// Removing through the scope entity acts on a foreign id.
func DropRepo(ctx *context.Context) {
	repoID := ctx.PathParam("repoid")
	err := ctx.Org.Team.RemoveRepository(ctx, repoID)
	_ = err
}

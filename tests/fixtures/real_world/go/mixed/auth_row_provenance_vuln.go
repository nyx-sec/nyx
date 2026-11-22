package repo

import (
	"example.com/models/packages"
	"example.com/models/repo"
	"example.com/services/context"
)

// The repo is found by a bare request-supplied name with nothing pinning it
// to the caller, so deleting by its id reports.
func DeleteByName(ctx *context.Context) {
	r, err := repo.GetRepoByName(ctx, ctx.PathParam("name"))
	if err != nil {
		return
	}
	repo.DeleteRepoByID(ctx, r.ID)
}

// A raw path id handed straight to the DAO reports.
func GetHookRaw(ctx *context.APIContext) {
	hookID := ctx.PathParam("id")
	hook, err := packages.GetHook(hookID)
	_, _ = hook, err
}

package repo

import (
	"example.com/models/auth"
	"example.com/models/packages"
	"example.com/services/context"
)

// pv comes from a lookup pinned to the package owner, so its ID is a row
// attribute.
func DeletePackageFile(ctx *context.Context) {
	owner := ctx.Package.Owner
	pv, err := packages.GetVersionByNameAndVersion(ctx, owner.ID, 1, ctx.PathParam("name"), ctx.PathParam("version"))
	if err != nil {
		return
	}
	pf, err := packages.GetFileForVersionByName(ctx, pv.ID, ctx.PathParam("filename"), "")
	_, _ = pf, err
}

// t is a row from a repo-scoped query.
func Sweep(ctx *context.Context) {
	tasks, err := auth.FindTasks(ctx, ctx.Repo.Repository.ID)
	_ = err
	for _, t := range tasks {
		a, _ := auth.GetUserByID(ctx, t.UserID)
		_ = a
	}
}

// Gitea-style handlers whose repo, organisation and package owner come from
// the request context.  The router middleware resolved them from the URL and
// checked the caller's access, so their ids are scope, not foreign input, and
// ctx.Doer is the signed-in user.  A lookup that also binds the scope entity
// is confined to it.  Pinned in `auth_analysis_tests`.
package repo

import (
	"strconv"

	"example.com/models/auth"
	"example.com/models/issues_model"
	"example.com/models/repo_model"
	"example.com/services/context"
)

func GetReleaseByTag(ctx *context.APIContext) {
	tag := ctx.PathParam("tag")
	release, err := repo_model.GetRelease(ctx, ctx.Repo.Repository.ID, tag)
	_, _ = release, err
}

func EnrollTwoFactor(ctx *context.Context) {
	name := ctx.PathParam("name")
	t, err := auth.GetTwoFactorByUID(ctx, ctx.Doer.ID)
	_, _, _ = t, err, name
}

func GetLabel(ctx *context.APIContext) {
	labelID, _ := strconv.ParseInt(ctx.PathParam("id"), 10, 64)
	l, err := issues_model.GetLabelInRepoByID(ctx, ctx.Repo.Repository.ID, labelID)
	_, _ = l, err
}

func GetLabelForRepo(ctx *context.APIContext, repo *repo_model.Repository) {
	labelID, _ := strconv.ParseInt(ctx.PathParam("id"), 10, 64)
	l, err := issues_model.GetLabelInRepoByID(ctx, repo.ID, labelID)
	_, _ = l, err
}

func GetPackageVersion(ctx *context.Context) {
	name := ctx.PathParam("name")
	owner := ctx.Package.Owner
	pv, err := packages_model.GetVersionByNameAndVersion(ctx, owner.ID, name, "1")
	_, _ = pv, err
}

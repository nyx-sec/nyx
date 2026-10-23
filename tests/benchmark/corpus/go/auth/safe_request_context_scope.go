package repo

import (
	"strconv"

	"example.com/models/auth"
	"example.com/models/issues_model"
	"example.com/models/repo_model"
	"example.com/services/context"
)

// The repo comes from the request context, resolved and access-checked by the
// router before the handler runs, so its id is scope and ctx.Doer is the
// signed-in user.
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

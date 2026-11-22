package repo

import (
	user_model "example.com/models/user"
	"example.com/services/context"
)

func ShowCommit(ctx *context.Context) {
	sha := ctx.PathParam("sha")
	c, err := ctx.Repo.GitRepo.GetCommit(sha)
	_, _ = c, err
}

func ShowSelf(ctx *context.Context) {
	id := ctx.Session.Get("uid").(int64)
	u, err := user_model.GetUserByID(ctx, id)
	_, _ = u, err
}

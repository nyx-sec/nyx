package repo

import (
	user_model "example.com/models/user"
	"example.com/services/context"
)

func ShowUser(ctx *context.Context) {
	uid := ctx.PathParam("uid")
	u, err := ctx.Repo.Repository.GetUserByID(ctx, uid)
	_, _ = u, err
}

func ShowMember(ctx *context.Context) {
	o := ctx.Org.Organization
	uid := ctx.PathParam("uid")
	m, err := o.GetMemberByID(ctx, uid)
	_, _ = m, err
}

func ShowConditional(ctx *context.Context) {
	id := ctx.PathParam("id")
	if ctx.Query("me") != "" {
		id = ctx.Session.Get("uid").(int64)
	}
	u, err := user_model.GetUserByID(ctx, id)
	_, _ = u, err
}

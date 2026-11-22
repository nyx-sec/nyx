package repo

import (
	"example.com/models/repo"
	user_model "example.com/models/user"
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

// A user fetched by id through the scope entity reads the global user table.
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

// A name first bound to something else does not keep the scope tag.
func ShowRebound(ctx *context.Context) {
	o := lookupOther(ctx.PathParam("org"))
	o = ctx.Org.Organization
	labelID := ctx.PathParam("label")
	l, err := o.GetLabelByID(ctx, labelID)
	_, _ = l, err
}

// One branch reads the id from the session, the other from the request.
func ShowConditional(ctx *context.Context) {
	id := ctx.PathParam("id")
	if ctx.Query("me") != "" {
		id = ctx.Session.Get("uid").(int64)
	}
	u, err := user_model.GetUserByID(ctx, id)
	_, _ = u, err
}

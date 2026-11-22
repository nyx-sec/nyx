package auth

import (
	"example.com/models/user"
	"example.com/services/context"
)

// Recall guard for safe_session_store_identity.go: an id from the URL.
func Profile(ctx *context.Context) {
	id := ctx.PathParam("userid")
	u, err := user.GetUserByID(ctx, id)
	_, _ = u, err
}

// A session key that is not the caller's own id stays untrusted.
func Impersonated(ctx *context.Context) {
	target := ctx.Session.Get("impersonatedUid")
	id := target.(int64)
	u, err := user.GetUserByID(ctx, id)
	_, _ = u, err
}

// A request form read is not the session store.
func FromForm(ctx *context.Context) {
	id := ctx.Req.Form.Get("uid")
	u, err := user.GetUserByID(ctx, id)
	_, _ = u, err
}

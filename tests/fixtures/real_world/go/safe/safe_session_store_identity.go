package auth

import (
	"errors"

	"example.com/models/auth"
	"example.com/services/context"
)

// The 2FA uid is written to the server-side session after the password check,
// so the client cannot choose it.
func TwoFactorPost(ctx *context.Context) {
	idSess := ctx.Session.Get("twofaUid")
	if idSess == nil {
		ctx.ServerError("x", errors.New("not in 2FA session"))
		return
	}
	id := idSess.(int64)
	twofa, err := auth.GetTwoFactorByUID(ctx, id)
	_, _ = twofa, err
}

func SessionUser(ctx *context.Context) {
	sess := ctx.Session
	uid := sess.Get("uid")
	if id, ok := uid.(int64); ok {
		u, err := auth.GetUserByID(ctx, id)
		_, _ = u, err
	}
}

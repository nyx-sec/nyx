// Recall guard for `go_ctx_scope_clean.go`: the same handler shape without a
// scope id still reaches a lookup by a request-supplied id.  Pinned in
// `auth_analysis_tests`.
package repo

import (
	"strconv"

	"example.com/models/issues_model"
	"example.com/services/context"
)

func GetLabelByID(ctx *context.APIContext) {
	labelID, _ := strconv.ParseInt(ctx.PathParam("id"), 10, 64)
	l, err := issues_model.GetLabelByID(ctx, labelID)
	_, _ = l, err
}

func GetFromForm(ctx *context.APIContext) {
	_ = ctx.Req.FormValue("id")
	l, err := issues_model.GetLabelByID(ctx, ctx.Req.Form.ID)
	_, _ = l, err
}

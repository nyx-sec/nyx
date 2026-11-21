// Recall guard for `go_fetch_then_authorize_clean.go`: the same fetch with no
// authorization on the row still fires.  Pinned in `auth_analysis_tests`.
package repo

import (
	"example.com/models/issues_model"
	"example.com/services/context"
)

func ViewIssue(ctx *context.Context) {
	id := ctx.PathParam("id")
	issue, err := issues_model.GetIssueByID(ctx, id)
	if err != nil {
		return
	}
	_ = issue
}

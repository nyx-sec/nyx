// Fetch the row by id, then authorize on the row.  The permission check sits
// after the fetch, so it covers the fetch itself.  Pinned in
// `auth_analysis_tests`.
package repo

import (
	"example.com/models/issues_model"
	"example.com/services/context"
)

func DeleteIssue(ctx *context.Context) {
	id := ctx.PathParam("id")
	issue, err := issues_model.GetIssueByID(ctx, id)
	if err != nil {
		return
	}
	if !CheckOwnership(ctx, issue) {
		return
	}
	issues_model.DeleteIssue(ctx, issue.ID)
}

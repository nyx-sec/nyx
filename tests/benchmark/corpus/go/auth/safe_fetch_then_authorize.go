package repo

import (
	"example.com/models/issues_model"
	"example.com/services/context"
)

// Fetch the row by id, then authorize on the row: the check covers the fetch.
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

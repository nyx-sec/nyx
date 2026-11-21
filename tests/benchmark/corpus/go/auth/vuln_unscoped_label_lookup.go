package repo

import (
	"strconv"

	"example.com/models/issues_model"
	"example.com/services/context"
)

// Recall guard for safe_request_context_scope.go: the same handler without a
// scope id looks the label up by the request-supplied id alone.
func GetLabel(ctx *context.APIContext) {
	labelID, _ := strconv.ParseInt(ctx.PathParam("id"), 10, 64)
	l, err := issues_model.GetLabelByID(ctx, labelID)
	_, _ = l, err
}

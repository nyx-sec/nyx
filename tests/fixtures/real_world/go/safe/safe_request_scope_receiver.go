package repo

import (
	"example.com/services/context"
)

// The router middleware resolved ctx.Repo and checked the caller's access to
// it, so reading a commit through it cannot leave that repository.
func CherryPick(ctx *context.Context) {
	fromCommitID := ctx.PathParam("sha")
	c, err := ctx.Repo.GitRepo.GetCommit(fromCommitID)
	_, _ = c, err
}

// The alias keeps the scope of the chain it was copied from.
func ShowCommit(ctx *context.Context) {
	gitRepo := ctx.Repo.GitRepo
	commitID := ctx.PathParam("sha")
	c, err := gitRepo.GetCommit(commitID)
	_, _ = c, err
}

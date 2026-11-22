package auth

import (
	"example.com/services/context"
)

type Store struct{}

func (s *Store) Add(token string, id string) error { return nil }

var tokenStore *Store

// Recall guard for safe_package_level_cache.go: a package-level value of an
// application type is not an in-memory container.
func Remember(ctx *context.Context) {
	token := ctx.PathParam("token")
	id := ctx.PathParam("id")
	_ = tokenStore.Add(token, id)
}

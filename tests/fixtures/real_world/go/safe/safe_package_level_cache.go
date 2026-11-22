package auth

import (
	lru "github.com/hashicorp/golang-lru/v2"

	"example.com/services/context"
)

var tokenCache *lru.Cache[string, any]

var seen = make(map[string]string)

// Both receivers are package-level in-memory containers, so recording the
// request token in them is process bookkeeping, not a data-layer write.
func Remember(ctx *context.Context) {
	token := ctx.PathParam("token")
	id := ctx.PathParam("id")
	if tokenCache != nil {
		tokenCache.Add(token, id)
	}
	seen[token] = id
}

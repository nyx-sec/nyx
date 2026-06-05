package graph

import "context"

// import "github.com/99designs/gqlgen/graphql"
type queryResolver struct{}

func (r *queryResolver) User(ctx context.Context, id string) (string, error) {
	return id, nil
}

func NormalizeID(id string) string {
	return id
}

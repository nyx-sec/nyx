package main

// Real-repo precision (2026-05-03): recall guard for the 2026-05-03
// type-aware Go param filter.
//
// Even after `ctx context.Context` is dropped from `unit.params`, an
// id-shaped param (`id string`) keeps the unit on the hook ─
// `is_external_input_param_name` recognises id-shapes ahead of the
// framework-name allow-list.  This fixture asserts that the type-aware
// filter doesn't over-suppress: a helper that takes the canonical
// `(ctx, id)` shape and consumes `id` at a bare-receiver data-layer
// sink must still fire `go.auth.missing_ownership_check`.

import "context"

type Repo struct{}

func (r *Repo) Find(id string) interface{} { return nil }
func (r *Repo) Save(id string, val string) {}

// `ctx context.Context` is dropped by the type-aware Go param filter
// (stdlib non-user-input).  `id string` survives ─ id-shape opens the
// gate.  `repo.Find(id)` is a bare-identifier read indicator with no
// preceding ownership check.  Rule must fire.
func GetByID(ctx context.Context, repo *Repo, id string) interface{} {
	_ = ctx
	return repo.Find(id)
}

// Mutation counterpart.
func UpdateByID(ctx context.Context, repo *Repo, id string, val string) {
	_ = ctx
	repo.Save(id, val)
}

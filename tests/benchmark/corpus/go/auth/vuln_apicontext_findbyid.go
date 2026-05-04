package main

// Real-repo precision (2026-05-03): recall guard for the type-aware Go
// param filter (2026-05-03 + 2026-05-03 expansion).
//
// 2026-05-03 update: the engine now drops id-like scalar params from
// `unit.params` for non-route units (gitea `models/...` DAO cluster,
// ~957 FPs).  This fixture asserts that the route-aware path keeps
// firing on the real vulnerable shape: a gin route handler whose body
// passes an id-shaped path param straight into a bare-receiver
// data-layer call with no preceding ownership check.
//
// `function_params_route_handler` runs with `include_id_like_typed =
// true`, so even after the DAO-shape filter the id-like scalar param
// survives in `unit.params` for `RouteHandler` units, the rule fires.

import "context"

type Repo struct{}

func (r *Repo) Find(id string) interface{} { return nil }
func (r *Repo) Save(id string, val string) {}

type ginEngine struct{}

func (g *ginEngine) GET(path string, handler interface{})  {}
func (g *ginEngine) POST(path string, handler interface{}) {}

// `ctx context.Context` is dropped by the type-aware Go param filter
// (stdlib non-user-input).  `id string` survives because the gin
// extractor promotes this unit to `RouteHandler` and route-aware param
// extraction keeps id-like names.  `repo.Find(id)` is a bare-identifier
// read indicator with no preceding ownership check — rule fires.
func GetByID(ctx context.Context, repo *Repo, id string) interface{} {
	_ = ctx
	return repo.Find(id)
}

// Mutation counterpart.
func UpdateByID(ctx context.Context, repo *Repo, id string, val string) {
	_ = ctx
	repo.Save(id, val)
}

// Gin route binding promotes both handlers to `RouteHandler` kind.
func registerRoutes(r *ginEngine) {
	r.GET("/items/:id", GetByID)
	r.POST("/items/:id", UpdateByID)
}

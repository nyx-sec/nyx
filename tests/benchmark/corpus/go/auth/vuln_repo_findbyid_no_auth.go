package main

// Real-repo precision (2026-04-27): companion vulnerable counterpart to
// `safe/safe_chained_call_response_header.go`.
//
// The chained-call suppression added in
// `src/auth_analysis/config.rs::classify_sink_class` only gates the
// verb-name fallback on shapes whose receiver is itself a call result
// (`w.Header().Get(..)`).  Bare-identifier receivers like `repo.Find`
// remain canonical data-layer sinks and must continue to fire
// `go.auth.missing_ownership_check` when invoked with a scoped
// identifier (`id` parameter) without a preceding ownership check.
//
// 2026-05-03 update: previously the helper signature alone
// (`func GetByID(ctx, repo, id string)`) was the recall guard.  After
// the Go DAO-helper precision pass (id-like scalar params dropped from
// `unit.params` for non-route units) the helper-only shape no longer
// passes `unit_has_user_input_evidence` — which is correct, the gitea
// `models/...` cluster proved that internal DAO helpers should not
// flag.  This fixture is now a real route-handler shape: the gin
// extractor recognises `r.GET(..., GetByID)` as a route registration,
// promotes the unit to `RouteHandler`, and `function_params_route_handler`
// keeps the id-like scalar param so the rule still fires on the actual
// vulnerable form (HTTP route binding directly to a DAO call with no
// preceding auth check).

type Repo struct{}

func (r *Repo) Find(id string) interface{} { return nil }
func (r *Repo) Save(id string, val string) {}

type ginEngine struct{}

func (g *ginEngine) GET(path string, handler interface{})  {}
func (g *ginEngine) POST(path string, handler interface{}) {}

// `repo.Find(id)` — bare-identifier receiver, name matches the `Find`
// read indicator.  Still classifies as `DbCrossTenantRead` and still
// fires the ownership check because no auth check precedes it.
func GetByID(ctx interface{}, repo *Repo, id string) interface{} {
	return repo.Find(id)
}

// `repo.Save(id, ..)` — bare-identifier receiver, mutation indicator.
func UpdateByID(ctx interface{}, repo *Repo, id string, val string) {
	repo.Save(id, val)
}

// Route registration: gin extractor recognises `r.GET(...)` /
// `r.POST(...)`, attaches `GetByID` / `UpdateByID` as the route
// handlers, and promotes their units to `AnalysisUnitKind::RouteHandler`.
// The id-like scalar param `id string` survives into `unit.params` via
// `function_params_route_handler` (route-aware, `include_id_like_typed = true`).
func registerRoutes(r *ginEngine) {
	r.GET("/items/:id", GetByID)
	r.POST("/items/:id", UpdateByID)
}

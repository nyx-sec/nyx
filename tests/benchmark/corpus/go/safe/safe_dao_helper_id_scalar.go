package main

// Real-repo precision (2026-05-03): distilled from
// /Users/elipeter/oss/gitea/models/actions/{run,run_job,runner,artifact,
// run_attempt,task,variable}.go and ~957 sibling helpers across gitea's
// `models/...` data-access layer.  Same shape over-fires on minio's
// `cmd/iam-*-store` and is the canonical Go ORM/DAO helper signature.
//
// Pattern: a model-layer helper takes the canonical Go first-param
// `ctx context.Context` (stdlib cancellation / deadline / value-bag,
// NOT an HTTP request) plus one or more id-like scalar parameters
// (`repoID, runID int64`, `id int64`, …).  The helper itself is
// **never** registered as a route handler — gitea's HTTP routes live
// in `routers/`, and the bound route handler runs the auth check
// before calling into `models/`.  The DAO helper inherits trust from
// its single caller surface and must not flag
// `go.auth.missing_ownership_check`.
//
// Engine fix (2026-05-03, src/auth_analysis/extract/common.rs::
// collect_param_names Go arm): for non-route units (default
// `include_id_like_typed = false`), drop id-like param names whose
// declared type is a bounded primitive scalar (`int*` / `uint*` /
// `string` / `bool` / `byte` / `rune` / `float*`).  Real Go HTTP
// handlers always carry a framework-request-typed param
// (`*http.Request`, `*gin.Context`, `echo.Context`, `*fiber.Ctx`,
// `*context.APIContext`, …) and are recognised by the per-framework
// route extractors which call `function_params_route_handler`
// (`include_id_like_typed = true`) — those bypass the filter so id-shaped
// path params survive on real routes (see
// `auth/vuln_apicontext_findbyid.go` and
// `auth/vuln_repo_findbyid_no_auth.go` for the recall guards).
//
// Conservative scope: only **bounded primitive scalar** types trigger
// the drop.  Pointer types (`*Runner`), struct-by-value, slice (`[]T`),
// generic and qualified types are payload shapes whose injection
// surface is unknown — id-like names on those keep their place in
// `unit.params`.

import "context"

type ActionRun struct{ ID int64 }
type ActionRunJob struct{ ID int64 }
type ActionRunner struct{ ID int64 }

type modelDB struct{}

func (m *modelDB) Find(ctx context.Context, id int64) interface{}     { return nil }
func (m *modelDB) DeleteByID(ctx context.Context, id int64) error     { return nil }
func (m *modelDB) UpdateRunJob(ctx context.Context, j *ActionRunJob)  {}

var db = &modelDB{}

// `(ctx context.Context, repoID, runID int64)` — multi-name single-type
// declaration with all bounded scalar params.  After the fix:
// `unit.params` is empty; `unit_has_user_input_evidence` returns false;
// `check_ownership_gaps` skips the unit entirely.
func GetRunByRepoAndID(ctx context.Context, repoID, runID int64) (*ActionRun, error) {
	_ = db.Find(ctx, runID)
	_ = repoID
	return &ActionRun{ID: runID}, nil
}

// Single id-like scalar param.  Same DAO-helper shape, must not flag
// even though `db.DeleteByID` and `GetRunnerByID` both look like
// canonical mutation/read indicators.
func DeleteRunner(ctx context.Context, id int64) error {
	if _, err := GetRunnerByID(ctx, id); err != nil {
		return err
	}
	return db.DeleteByID(ctx, id)
}

func GetRunnerByID(ctx context.Context, id int64) (*ActionRunner, error) {
	_ = db.Find(ctx, id)
	return &ActionRunner{ID: id}, nil
}

// Mixed-arity helper: `userID int64` (id-like + scalar, dropped) plus
// `cfg *ActionRun` (non-scalar payload, kept).  `cfg` is not id-like
// and doesn't match the Go-narrowed framework-name allow-list, so the
// unit still has no evidence and the rule does not flag.
func SetOwnerActionsConfig(ctx context.Context, userID int64, cfg *ActionRun) error {
	_ = userID
	_ = cfg
	_ = ctx
	return nil
}

package main

// Real-repo precision (2026-05-03): distilled from
// /Users/elipeter/oss/gitea/services/packages/packages.go::AddFileToExistingPackage
// and ~1900 sibling helpers across gitea, hugo, minio, harbor.
//
// Pattern: a backend service helper takes the canonical Go first-param
// `ctx context.Context` (stdlib cancellation / deadline / value-bag,
// NOT an HTTP request) and an internally-typed payload struct.  The
// helper itself is not a route handler ─ routes live one layer up
// where `ctx *context.APIContext` (gitea-specific) carries the
// request.  Without the type-aware Go param filter, the bare param
// name `ctx` matched the framework-request-name allow-list in
// `is_external_input_param_name`, opening
// `unit_has_user_input_evidence` on every helper and firing
// `go.auth.missing_ownership_check` on every internal id-shaped sink.
//
// Engine fix (2026-05-03): two-layer Go narrowing.
//   * Layer 1 (structural, src/auth_analysis/extract/common.rs):
//     `parameter_declaration` arm drops the entire param when its
//     type is the stdlib `context.Context` / `context.CancelFunc`.
//     Type-segment idents (e.g. `PackageInfo` from `*PackageInfo`)
//     are also no longer leaked.
//   * Layer 2 (classifier, src/auth_analysis/checks.rs):
//     `is_external_input_param_name_for_lang` narrows Go's allow-list
//     to `req` / `request` only ─ Go has no framework convention that
//     uses the generic typed-extractor names from JS/TS/Python.

import (
	"context"
	"errors"
)

type PackageInfo struct{ ID int64 }

// `AddFileToExistingPackage` is a backend helper, never reachable
// directly from the network.  Its only "user-input evidence" was the
// stdlib `ctx context.Context` ─ a cancellation primitive.  The
// type-aware filter drops the param.
func AddFileToExistingPackage(ctx context.Context, info *PackageInfo) (*PackageInfo, error) {
	if info == nil {
		return nil, errors.New("nil")
	}
	return getByID(ctx, info.ID)
}

// `getByID` is invoked with `info.ID` from the caller.  Both params
// are dropped at the type-aware filter (`ctx context.Context`) or
// surface only as a numeric type whose name doesn't trip the gate.
func getByID(ctx context.Context, id int64) (*PackageInfo, error) {
	_ = ctx
	return &PackageInfo{ID: id}, nil
}

// CLI command shape used by gitea/cmd: `ctx context.Context` plus a
// urfave/cli command argument.  Pure admin entry-point, no HTTP path.
type cliCommand struct{}

func runRepoSyncReleases(ctx context.Context, _ *cliCommand) error {
	_ = ctx
	return nil
}

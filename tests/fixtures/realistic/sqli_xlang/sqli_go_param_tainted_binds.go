// Phase 15 deferred-fix negative — Go database/sql `db.QueryContext`
// parameterised with a TAINTED bind value.  The SQL string at arg 1
// (after `ctx`) is a literal with `$1` placeholder; the user-controlled
// `name` is sent as a separate positional parameter at arg 2, which
// `database/sql` routes through the driver's parameterised path.
//
// Without payload-arg gating on `db.QueryContext` (Phase 15 deferred fix
// in `labels/go.rs::GATED_SINKS`), the flat `db.QueryContext` rule would
// fire SQLi on `name`'s flow into arg 2.  The Destination gate restricts
// `sink_payload_args` to `&[1]`, silencing taint at arg 2+.
package main

import (
	"context"
	"database/sql"
	"net/http"
)

func lookup(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	name := r.URL.Query().Get("name")
	rows, _ := db.QueryContext(context.Background(), "SELECT * FROM users WHERE name = $1", name)
	_ = rows
}

// Phase 10 (Track D.3) stub-end-to-end fixture: Go + SQL.
//
// Body-only fragment, not a standalone `go run`-able program.  The
// companion test in `tests/stubs_e2e_per_lang.rs` wraps these lines
// in `package main` + the union of stdlib imports required by both
// the spliced probe shim and this fragment, places the Go probe
// shim ahead of `func main`, and then invokes `go run` on the
// resulting file.
//
// The verifier publishes:
//
//   NYX_SQL_ENDPOINT — absolute path of a SQLite DB the SqlStub owns.
//   NYX_SQL_LOG      — companion log path the harness appends executed
//                      queries to so the host SqlStub picks them up on
//                      drain_events() even when the harness never opens
//                      an on-the-wire driver (no go-sqlite3 / pgx /
//                      mysql dep on the dynamic CI matrix; query
//                      pre-flighted before sql.Open).
//
// This fragment records the tautology query through the Go shim
// helper __nyx_stub_sql_record as `driver = "manual"` so the test
// stays stdlib-only — no `database/sql` import, no go.mod driver
// dep, no libsqlite3-dev system package.  Mirrors the Phase 26
// "no live driver available" path that real Go sink callsites take
// when the build matrix lacks a driver.
query := "SELECT 1 WHERE 'a' = 'a' OR 1=1 --"
__nyx_stub_sql_record(query, map[string]string{"driver": "manual"})
// Echo so the host can confirm the driver ran end-to-end.
fmt.Print(os.Getenv("NYX_SQL_ENDPOINT"))

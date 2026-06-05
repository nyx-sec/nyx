# Phase 10 (Track D.3) stub-end-to-end fixture: Ruby + SQL.
#
# The verifier publishes:
#
#   * NYX_SQL_ENDPOINT — absolute path of a SQLite DB the SqlStub owns.
#   * NYX_SQL_LOG      — companion log path the harness appends executed
#     queries to so the host SqlStub picks them up on drain_events()
#     even when the harness never opens an on-the-wire driver (sqlite3
#     gem absent on minimal CI images, query pre-flighted before
#     SQLite3::Database.open).
#
# This fixture stays gem-free by recording the tautology through
# __nyx_stub_sql_record as driver = 'manual'.  No sqlite3 require, no
# Gemfile dep, no Prerequisite::GemAvailable variant required.  Mirrors
# the Phase 26 "no live driver available" path that real Ruby sink
# callsites take when the build matrix lacks a driver.

query = "SELECT 1 WHERE 'a' = 'a' OR 1=1 --"
__nyx_stub_sql_record(query, driver: 'manual')
# Echo so the host can confirm the driver ran end-to-end.
$stdout.puts(ENV['NYX_SQL_ENDPOINT'] || 'no-endpoint')

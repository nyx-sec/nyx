# scc_summary_cycle_stops_early

## Purpose
Reduced from gogs `internal/ssh/ssh.go`. `listen` calls the standard
library's `net.Listen(...)`, which name-based resolution binds to this
file's own `Listen`, and `Listen` starts `listen`, so the pair forms a
recursive group. Their SSA summaries then alternate between two states on
every fixed-point iteration (`source_caps` and `param_to_return` flip), so
the loop can never converge. It used to run all 64 iterations; it now
notices the repeated state and stops after a few.

## Expectations
- The fixed-point loop stops well below the 64-iteration cap.
- Findings of the cycling group carry the `scc_unconverged` note with
  `reason=suspected_oscillation`. If resolution or extraction stops the
  pair from cycling, the loop converges instead and nothing is tagged.

# scc_sink_order_oscillation

## Purpose
Two recursive pairs whose sink sites reach each other through the
recursive call: `serveHTTP` / `handleError` in `main.go` (reduced from
caddy's admin handler) and `processNested` / `processWhere` in `where.js`
(reduced from strapi's where-clause builder). Summary extraction appended
those sites in the order the callee summary listed them, so every
fixed-point iteration flipped the order back, the summaries never compared
equal, and both batches ran to the 64-iteration cap with every finding
tagged `scc_unconverged`. Summaries are now compared on their facts, not on
the order of those sites, so both converge within a handful of iterations.

## Expectations
- The fixed-point loop converges well below the cap.
- No finding carries the `scc_unconverged` note.

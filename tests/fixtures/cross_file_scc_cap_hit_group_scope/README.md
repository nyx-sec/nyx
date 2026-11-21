# cross_file_scc_cap_hit_group_scope

## Purpose
The four-file `step_a -> step_b -> step_c -> step_d -> step_a` cycle from
`cross_file_scc_deep_cycle`, plus `walker.py`, a self-recursive file that
shares no SCC with the cycle. Both sit on the same level of the file
dependency DAG, so pass 2 runs them in one fixed-point batch. When the
fixed-point cap is forced low, only the cycle's findings may carry the
`scc_unconverged` tag; `walker.py` converged and keeps its confidence.

## Expectations
- **required**: `taint-unsanitised-flow` (>=2: one in `walker.py`, one in `server.py`; the test checks each file)
- **forbidden**: (none)
- **noise_budget**: max_total=20, max_high=10

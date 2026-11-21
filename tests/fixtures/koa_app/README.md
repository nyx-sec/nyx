# koa_app

## Purpose
Realistic Koa.js web app fixture used as a multi-file scan regression.

## Expectations
- **required**: `taint-unsanitised-flow` (≥1, the echoed body) and `taint-open-redirect` (≥1, the redirect)
- **forbidden**: (none)
- **noise_budget**: max_total=6, max_high=4

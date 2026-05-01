"""demand_driven_data_exfil.

`Cap::DATA_EXFIL` parity for the backwards-analysis pass.  The forward
engine emits a `taint-data-exfiltration` finding for the cookie →
fetch-body flow (Sensitive source, fixed destination URL).  With
`backwards_analysis = true`, the post-pass must walk backwards from the
DATA_EXFIL sink demand, reach the cookie source, and annotate the
finding with `backwards-confirmed`.  Validates that the cap-routing
logic in `taint/backwards.rs::DemandState` round-trips bit 13
(DATA_EXFIL) identically to the SQL/CMD/SSRF caps the rest of the
demand-driven suite covers.
"""

import requests
from flask import request


def forward_session():
    sid = request.cookies.get("session")
    requests.post("https://analytics.internal/track", json={"session": sid})

// Phase 08 negative: the two-arg `new URL(path, base)` shape with a fixed
// `/v2/` head on the path produces an origin-locked AbstractValue whose
// StringFact prefix includes the literal scheme/host.  The head makes the
// path an absolute-path reference, which keeps the base host whatever the
// attacker appends, so `is_string_safe_for_ssrf` honours the lock and
// suppresses the SSRF sink.  (A bare attacker path does not lock: it can be
// `https://evil/` or `//evil/`; see `ssrf_new_url_with_base.ts`.)
import express from "express";

const app = express();

app.post("/api", (req: express.Request, res: express.Response): void => {
    const u = new URL(`/v2/${req.body.path}`, "https://api.cal.com");
    u.searchParams.set("redirect", req.body.dest);
    fetch(u);
    res.status(204).end();
});

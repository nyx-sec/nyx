// Phase 08 negative — the two-arg `new URL(path, "https://api.cal.com")`
// shape produces an origin-locked AbstractValue whose StringFact prefix
// includes the literal scheme/host.  `is_string_safe_for_ssrf` honours
// the lock and suppresses the SSRF sink even though the path component
// is attacker-controlled.
import express from "express";

const app = express();

app.post("/api", (req: express.Request, res: express.Response): void => {
    const u = new URL(req.body.path, "https://api.cal.com");
    u.searchParams.set("redirect", req.body.dest);
    fetch(u);
    res.status(204).end();
});

// Phase 08 fixture — `fetch(target)` where `target` is bound to a URL
// instance whose path was attacker-controlled at construction time.
// The first positional argument carries TypeKind::Url, and the
// constructor-propagation rule pushes the path-arg taint into the URL
// value so the tainted SSA value reaches the SSRF sink without an
// intermediate string coercion.
import express from "express";

const app = express();

app.post("/proxy", (req: express.Request, res: express.Response): void => {
    const target: URL = new URL(req.body.endpoint);
    fetch(target);
    res.status(204).end();
});

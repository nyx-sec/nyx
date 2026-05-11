// Phase 08 fixture — `new URL(taintedPath)` with a single, attacker-
// controlled positional argument.  The constructor does not carry a label
// rule and has no summary, so without the URL-aware constructor-
// propagation pass added in Phase 08 the constructed URL would arrive
// untainted at the `fetch` sink and the SSRF would be missed.
import express from "express";

const app = express();

app.post("/proxy", (req: express.Request, res: express.Response): void => {
    const target = new URL(req.body.endpoint);
    fetch(target);
    res.status(204).end();
});

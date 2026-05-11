// Phase 08 fixture — `fetch({ url: tainted, ... })` Request-style object
// form. The destination-aware filter on the SSRF gate restricts taint
// checks to identifiers under the `url` field, so the tainted `target`
// triggers SSRF while the fixed `body` does not.
import express from "express";

const app = express();

app.post("/proxy", (req: express.Request, res: express.Response): void => {
    const target = req.body.target;
    fetch({
        url: target,
        method: "POST",
        body: "{}",
    });
    res.status(204).end();
});

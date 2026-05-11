// Phase 08 fixture — `u.searchParams.set(k, taintedV)` taints the
// underlying URL receiver.  The base URL string ("api/proxy") carries no
// scheme or leading slash so the abstract-string prefix lock cannot
// suppress SSRF, leaving the back-tainted URL to reach `fetch` as a
// genuine SSRF flow.
import express from "express";

const app = express();

app.post("/api", (req: express.Request, res: express.Response): void => {
    const u = new URL("api/proxy");
    u.searchParams.set("redirect", req.body.dest);
    fetch(u);
    res.status(204).end();
});

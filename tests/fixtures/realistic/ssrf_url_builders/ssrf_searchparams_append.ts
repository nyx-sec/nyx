// Phase 08 fixture — `.append(k, taintedV)` mirrors the `.set` rule:
// the searchParams view is treated as a TypeKind::Url alias, so the
// arg-side taint flows back through the FieldProj chain into the URL
// receiver and reaches the `fetch` SSRF sink.
import express from "express";

const app = express();

app.post("/api", (req: express.Request, res: express.Response): void => {
    const u = new URL("api/lookup");
    u.searchParams.append("term", req.body.term);
    fetch(u);
    res.status(204).end();
});

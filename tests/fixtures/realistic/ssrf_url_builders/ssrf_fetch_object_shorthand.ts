// Phase 08 follow-up — `fetch({ url })` object-shorthand and computed
// string-literal key forms. The destination filter and the call
// arg-uses lifter both need to recognise the shorthand_property_identifier
// node (object-literal `{ url }` is a USE of the local `url`,
// distinct from the destructuring pattern `{ url } = obj`) and the
// computed-string-literal key (`['url']`) for SSRF to fire.
import express from "express";

const app = express();

app.post("/proxy_shorthand", (req: express.Request, res: express.Response): void => {
    const url = req.body.target;
    fetch({ url });
    res.status(204).end();
});

app.post("/proxy_computed", (req: express.Request, res: express.Response): void => {
    const target = req.body.target;
    fetch({ ['url']: target });
    res.status(204).end();
});

// `new URL(path, base)` resolves `path` as a reference against `base`: an
// absolute (`https://evil/`) or protocol-relative (`//evil/`) path replaces the
// literal base's host.  A literal base alone therefore does not pin the origin
// when the path is attacker-controlled.
import express from "express";

const app = express();

app.post("/api", (req: express.Request, res: express.Response): void => {
    const u = new URL(req.body.path, "https://api.cal.com");
    fetch(u);
    res.status(204).end();
});

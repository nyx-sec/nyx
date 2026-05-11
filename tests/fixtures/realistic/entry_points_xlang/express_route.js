// Phase 16 fixture: Express route handler.  `app.post('/u', ...)`
// registers an arrow handler whose span is detected as an
// `ExpressRoute { method: POST }` entry point.  The seeding policy
// paints `req` and `res` as `Source(Cap::all())`; `req.body.name` is
// already a JS-handler-param-name source via Phase 05, so flowing
// into `db.query(...)` fires the SQL_QUERY sink.  The new entry-kind
// detection guarantees the seeding even outside Next.js.
const express = require('express');
const app = express();
const db = require('./db');

app.post('/u', (req, res) => {
    db.query("SELECT * FROM users WHERE name = '" + req.body.name + "'");
    res.send('ok');
});

module.exports = app;

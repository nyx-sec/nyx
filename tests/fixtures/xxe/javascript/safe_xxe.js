// Safe: tainted XML reaches xml2js.parseString with default options.
// xml2js does not expand external entities unless explicitly configured;
// the gate's dangerous_kwargs list (`processEntities`/`explicitEntities`/
// `strict`) is empty in the literal, so the gate suppresses the finding.
const xml2js = require("xml2js");

function handle(req, res) {
    const body = req.query.xml;
    xml2js.parseString(body, { explicitArray: false }, (err, result) => {
        res.json(result);
    });
}

module.exports = { handle };

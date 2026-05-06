// Unsafe: tainted XML reaches xml2js.parseString with `processEntities: true`,
// activating the XXE gate.
const xml2js = require("xml2js");

function handle(req, res) {
    const body = req.query.xml;
    xml2js.parseString(body, { processEntities: true }, (err, result) => {
        res.json(result);
    });
}

module.exports = { handle };

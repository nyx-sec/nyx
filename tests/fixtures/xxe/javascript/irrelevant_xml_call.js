// Baseline: tainted body flows through a non-parser string operation.
// No XML parser entry point, no XXE label classification.
function handle(req, res) {
    const body = req.query.xml;
    res.send("<wrap>" + body + "</wrap>");
}

module.exports = { handle };

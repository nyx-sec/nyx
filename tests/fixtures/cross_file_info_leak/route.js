const service = require("./service");

/**
 * VULN: service.getDebugInfo() returns process.env data (source-independent taint).
 * The return value flows to res.send() (HTML_ESCAPE sink).
 * Cross-file source_caps should propagate through the summary.
 */
function handleDebug(req, res) {
    const info = service.getDebugInfo(req);
    res.send(info);
}

const previewService = require("./previewService");

/**
 * VULN: req.query.url (user input) flows through previewService.fetchUrl()
 * which calls lib.request(url) where lib is dynamically http or https.
 * Module alias tracking should resolve lib.request → http.request (SSRF sink).
 */
function handlePreview(req, res) {
    const url = req.query.url;
    const result = previewService.fetchUrl(url);
    res.send(result);
}

// Safe-template-var: nunjucks.renderString gets a *constant* template
// source; only the data context (arg 1) carries user input.  Per the
// gated SSTI classifier (payload_args=[0]), this must NOT fire.
const nunjucks = require('nunjucks');

function handler(req, res) {
    const html = nunjucks.renderString('Hello, {{ name }}', {
        name: req.query.name,
    });
    res.send(html);
}

module.exports = handler;

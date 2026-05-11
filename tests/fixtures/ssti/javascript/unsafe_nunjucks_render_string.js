// Unsafe: nunjucks.renderString receives a tainted template *source*
// string (arg 0) built from req.body; SSTI fires on the source argument.
const nunjucks = require('nunjucks');

function handler(req, res) {
    const src = req.body.template;
    const html = nunjucks.renderString(src, { user: 'anon' });
    res.send(html);
}

module.exports = handler;

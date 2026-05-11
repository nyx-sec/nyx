// Unsafe: Handlebars.compile receives a template *source* string built from
// req.body.  SSTI fires on the source argument.
const Handlebars = require('handlebars');

function handler(req, res) {
    const tmpl = req.body.template;
    const compiled = Handlebars.compile(tmpl);
    res.send(compiled({}));
}

module.exports = handler;

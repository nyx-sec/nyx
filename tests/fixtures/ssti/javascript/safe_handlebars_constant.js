// Safe: Handlebars.compile receives a constant template source string.
// Variables provided at render time are not template source and do not
// activate SSTI.
const Handlebars = require('handlebars');

function handler(req, res) {
    const compiled = Handlebars.compile('Hello, {{name}}');
    res.send(compiled({ name: req.query.name }));
}

module.exports = handler;

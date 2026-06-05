// Phase 04 (Track J.2) — JavaScript Handlebars benign control fixture.
//
// Renders a fixed template that interpolates the body as a context
// variable; the user-controlled value never reaches the template
// compiler.
const Handlebars = require('handlebars');

const template = Handlebars.compile('{{safeBody}}');

function run(body) {
    return template({ safeBody: body });
}

module.exports = { run };

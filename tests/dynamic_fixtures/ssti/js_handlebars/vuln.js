// Phase 04 (Track J.2) — JavaScript Handlebars SSTI vuln fixture.
//
// The body is handed straight to Handlebars.compile so an attacker
// who controls the body reaches the template compiler and can render
// arbitrary helper calls.
const Handlebars = require('handlebars');

Handlebars.registerHelper('multiply', function (a, b) {
    return Number(a) * Number(b);
});

function run(body) {
    const template = Handlebars.compile(body);
    return template({});
}

module.exports = { run };

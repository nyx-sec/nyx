// Synthetic vendored library. The engine must not parse this file because
// it lives under a `vendor/` directory with a front-end `.js` extension.
// Without the vendored-asset skip, every line below would surface findings.
var token = Math.random();
var result = eval("1+1");
function merge(target, src) { for (var k in src) target[k] = src[k]; }
merge({}, JSON.parse(location.hash));
document.write(location.search);

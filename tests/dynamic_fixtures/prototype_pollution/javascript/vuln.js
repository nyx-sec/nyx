// Phase 10 (Track J.8) — JavaScript PROTOTYPE_POLLUTION vuln fixture.
//
// The handler parses an attacker-controlled JSON string and passes
// the parsed object into `lodash.merge` against a vanilla `{}`
// target.  When the payload's top-level key is `__proto__`, the
// merge walks the key into `Object.prototype` and the harness's
// canary trap records a `ProbeKind::PrototypePollution` probe.
const _ = require('lodash');

function deepMerge(target, source) {
  return _.merge(target, source);
}

function run(payload) {
  const parsed = JSON.parse(payload);
  const target = {};
  return deepMerge(target, parsed);
}

module.exports = { run };

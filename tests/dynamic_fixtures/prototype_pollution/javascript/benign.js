// Phase 10 (Track J.8) — JavaScript PROTOTYPE_POLLUTION benign
// control fixture.
//
// The handler parses an attacker-controlled JSON string and walks
// it into a target constructed via `Object.create(null)`.  Because
// the target has no prototype chain, even a payload whose top-level
// key is `__proto__` cannot reach `Object.prototype`.  The harness's
// canary trap stays clear and no `PrototypePollution` probe is
// emitted.
const _ = require('lodash');

function deepMerge(target, source) {
  return _.merge(target, source);
}

function run(payload) {
  const parsed = JSON.parse(payload);
  const target = Object.create(null);
  return deepMerge(target, parsed);
}

module.exports = { run };

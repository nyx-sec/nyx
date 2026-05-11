// Negative control: hand-authored production source must still be scanned.
// `Math.random` here MUST surface as `js.crypto.math_random` so the
// vendored-asset skip is proven not to over-suppress.
function makeToken() {
  return Math.random().toString(16).slice(2);
}

module.exports = { makeToken };

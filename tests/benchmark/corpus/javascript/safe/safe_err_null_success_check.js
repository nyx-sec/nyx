const fs = require('fs');

// `err === null` is a success check: the TRUE branch is the happy path, so
// the code after the `if` is not an error check falling through.
function refresh(err, data) {
  if (err === null) {
    console.log('loaded', data.length);
  }
  fs.unlinkSync('/var/cache/app/stale');
}

module.exports = { refresh };

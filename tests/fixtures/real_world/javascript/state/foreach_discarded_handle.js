const fs = require('fs');

function openEach(p) {
    [1, 2].forEach(x => fs.openSync(p, 'r'));
}

function openOne(p) {
    return () => fs.openSync(p, 'r');
}

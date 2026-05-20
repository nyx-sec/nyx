// Phase 19 (Track M.1) — class-method vuln fixture for JavaScript.
//
// UserService.run forwards a tainted string straight into child_process.exec,
// classic OS command injection.  Default ctor — no stubbed deps needed.
'use strict';
const { execSync } = require('child_process');

class UserService {
    constructor() {}
    run(input) {
        // SINK: untrusted input → shell
        return execSync('echo ' + input).toString();
    }
}

module.exports = { UserService };

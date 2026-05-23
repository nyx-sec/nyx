// Phase 19 (Track M.1) — class-method vuln fixture for TypeScript.
//
// UserService.run forwards user input directly to a shell.  The source
// stays CommonJS-compatible because the harness stages TS fixtures as
// entry.js for stock Node.
'use strict';
const { execSync } = require('child_process');

class UserService {
    constructor() {}
    run(input) {
        // SINK: untrusted input flows into the shell
        return execSync('true ' + input).toString();
    }
}

module.exports = { UserService };

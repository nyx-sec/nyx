// Phase 19 (Track M.1) — class-method benign control for TypeScript.
'use strict';
const { execFileSync } = require('child_process');

class UserService {
    constructor() {}
    run(input) {
        return execFileSync('true', [input]).toString();
    }
}

module.exports = { UserService };

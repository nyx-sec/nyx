// Phase 19 (Track M.1) — class-method benign control for JavaScript.
//
// UserService.run routes the input through execFileSync with argv form so
// the shell never interprets the string or echoes marker bytes.
'use strict';
const { execFileSync } = require('child_process');

class UserService {
    constructor() {}
    run(input) {
        return execFileSync('true', [input]).toString();
    }
}

module.exports = { UserService };

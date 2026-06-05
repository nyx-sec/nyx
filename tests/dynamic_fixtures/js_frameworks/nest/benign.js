// Phase 13 (Track L.11) — NestJS CMDI benign fixture.  Same adapter
// binding shape as the vuln fixture; the differential outcome is what
// distinguishes the two.

require('reflect-metadata');
const { Controller, Get, Query } = require('@nestjs/common');
const { execFile } = require('child_process');

const ALLOW = new Set(['status', 'uptime', 'version']);

@Controller('')
class AppController {
    @Get('run')
    runCmd(@Query('cmd') cmd) {
        if (!ALLOW.has(cmd || '')) {
            return 'rejected';
        }
        return new Promise((resolve) => {
            execFile('/usr/bin/echo', [cmd], (err, stdout) => {
                resolve(err ? String(err) : stdout);
            });
        });
    }
}

module.exports = { AppController };

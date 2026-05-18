// Phase 13 (Track L.11) — NestJS CMDI vuln fixture (Babel-stage-1
// decorator syntax form).  Real Nest projects publish their
// controllers either as `.ts` files or as Babel-transpiled `.js`
// carrying the inline decorator syntax via `@babel/plugin-proposal-decorators`
// + `reflect-metadata`.  The adapter binds the decorator syntax;
// the harness loads the entry via `Test.createTestingModule`.
//
// Adapter binding: `@Controller('')` + `@Get('run')` on
// `AppController.runCmd` with `cmd` flowing through `@Query('cmd')`.

require('reflect-metadata');
const { Controller, Get, Query } = require('@nestjs/common');
const { exec } = require('child_process');

@Controller('')
class AppController {
    @Get('run')
    runCmd(@Query('cmd') cmd) {
        return new Promise((resolve) => {
            exec(cmd || '', (err, stdout) => {
                resolve(err ? String(err) : stdout);
            });
        });
    }
}

module.exports = { AppController };

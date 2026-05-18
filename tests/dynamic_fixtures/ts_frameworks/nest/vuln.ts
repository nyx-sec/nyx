// Phase 13 (Track L.11) — NestJS CMDI vuln fixture (TypeScript).
//
// Adapter binding: `@Controller('')` + `@Get('run')` on
// `AppController.runCmd` with `cmd` flowing through `@Query('cmd')`.

import 'reflect-metadata';
import { Controller, Get, Query } from '@nestjs/common';
import { exec } from 'child_process';

@Controller('')
export class AppController {
    @Get('run')
    runCmd(@Query('cmd') cmd: string): Promise<string> {
        return new Promise((resolve) => {
            exec(cmd || '', (err, stdout) => {
                resolve(err ? String(err) : stdout);
            });
        });
    }
}

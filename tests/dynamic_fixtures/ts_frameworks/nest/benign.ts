// Phase 13 (Track L.11) — NestJS CMDI benign fixture (TypeScript).

import 'reflect-metadata';
import { Controller, Get, Query } from '@nestjs/common';
import { execFile } from 'child_process';

const ALLOW = new Set(['status', 'uptime', 'version']);

@Controller('')
export class AppController {
    @Get('run')
    runCmd(@Query('cmd') cmd: string): Promise<string> | string {
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

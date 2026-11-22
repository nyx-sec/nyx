import { Controller, Get, Query } from '@nestjs/common';
import { exec } from 'child_process';

// The `host` formal is filled from the query string by the @Query decorator,
// whatever the parameter is called.
@Controller('diag')
export class DiagController {
    @Get()
    ping(@Query('host') host: string) {
        exec(`ping -c 1 ${host}`);
    }
}

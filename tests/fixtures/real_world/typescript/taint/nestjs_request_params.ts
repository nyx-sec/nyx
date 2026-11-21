import { Body, Controller, Get, Headers, Param, Post, Query, Res } from '@nestjs/common';
import { exec } from 'child_process';
import { Response } from 'express';

class RunDto {
  script!: string;
}

@Controller('jobs')
export class JobsController {
  @Get('run')
  run(@Query('q') q: string) {
    exec(q);
  }

  @Get('file/:name')
  file(@Param('name') name: string, @Res() res: Response) {
    res.sendFile('/srv/' + name);
  }

  @Post()
  create(@Body() dto: RunDto) {
    exec(dto.script);
  }

  @Get('trace')
  trace(@Headers('x-trace') trace: string) {
    exec('echo ' + trace);
  }
}

export class JobsService {
  list(name: string) {
    exec('ls ' + name);
  }
}

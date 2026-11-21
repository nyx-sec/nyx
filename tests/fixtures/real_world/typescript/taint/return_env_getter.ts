import { exec } from 'child_process';

function getCommand(): string {
  return process.env.CMD as string;
}

export function run(): void {
  const cmd = getCommand();
  exec(cmd);
}

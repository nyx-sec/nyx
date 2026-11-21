import { writeFile, appendFile, copyFile } from 'node:fs/promises';
import type { Request, Response } from 'express';

export async function log(req: Request, res: Response) {
  await writeFile('/tmp/last.json', JSON.stringify(req.body));
  await appendFile('/var/log/app.log', String(req.query.msg));
  res.end();
}

export async function save(req: Request, res: Response) {
  const name = String(req.query.name);
  await writeFile(`/srv/uploads/${name}`, 'x');
  const dest = String(req.query.dest);
  await copyFile('/srv/template.txt', dest);
  res.end();
}

import express from 'express';
import { db } from './db';

const app = express();

function sql(strings: TemplateStringsArray, ...values: unknown[]): string {
  return strings.reduce((acc, s, i) => acc + s + (values[i] ?? ''), '');
}

function raw(value: string): string {
  return value;
}

app.get('/u1', async (req, res) => {
  const id = req.query.id as string;
  await db.query(sql`SELECT * FROM t WHERE id = ${id}`);
  res.status(200).end();
});

app.get('/u2', async (req, res) => {
  const col = req.query.col as string;
  await db.query(sql`SELECT ${raw(col)} FROM t`);
  res.status(200).end();
});

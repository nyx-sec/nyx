import express from 'express';
import { PrismaClient, Prisma } from '@prisma/client';
import { sql } from 'drizzle-orm';
import { db } from './db';

const prisma = new PrismaClient();
const app = express();

app.get('/p1', async (req, res) => {
  const email = req.query.email as string;
  await prisma.$queryRaw`SELECT * FROM "User" WHERE email = ${email}`;
  await prisma.$executeRaw`UPDATE "User" SET seen = true WHERE email = ${email}`;
  res.status(200).end();
});

app.get('/d1', async (req, res) => {
  const name = req.query.name as string;
  await db.execute(sql`select * from users where name = ${name}`);
  const q = sql`select * from users where name = ${name}`;
  await db.execute(q);
  res.status(200).end();
});

app.get('/d2', async (req, res) => {
  const col = req.query.col as string;
  await db.execute(sql.raw(`select ${col} from users`));
  await db.execute(sql`select ${sql.raw(col)} from users`);
  res.status(200).end();
});

app.get('/p2', async (req, res) => {
  const col = req.query.col as string;
  await prisma.$queryRaw`SELECT ${Prisma.raw(col)} FROM "User"`;
  await prisma.$queryRawUnsafe(`SELECT * FROM ${col}`);
  res.status(200).end();
});

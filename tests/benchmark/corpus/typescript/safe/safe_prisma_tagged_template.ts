import express from 'express';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const app = express();

// The tagged template sends `${email}` as a bind parameter.
app.get('/user', async (req, res) => {
    const email = req.query.email as string;
    await prisma.$queryRaw`SELECT * FROM "User" WHERE email = ${email}`;
    res.status(200).end();
});

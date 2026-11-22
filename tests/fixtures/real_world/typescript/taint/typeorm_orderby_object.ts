import express from 'express';
import { getRepository } from 'typeorm';
import { User } from './user';

const app = express();

app.get('/o1', async (req, res) => {
  const rows = await getRepository(User)
    .createQueryBuilder('u')
    .orderBy({ [req.query.sort as string]: 'ASC' })
    .getMany();
  res.json(rows);
});

app.get('/o2', async (req, res) => {
  const rows = await getRepository(User)
    .createQueryBuilder('u')
    .orderBy({ 'u.name': 'ASC', 'u.id': 'DESC' })
    .getMany();
  res.json(rows);
});

app.get('/o3', async (req, res) => {
  const sort = req.query.sort as string;
  const rows = await getRepository(User)
    .createQueryBuilder('u')
    .groupBy(new String(sort))
    .getMany();
  res.json(rows);
});

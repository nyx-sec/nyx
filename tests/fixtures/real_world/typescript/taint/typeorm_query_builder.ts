import express from 'express';
import { getRepository } from 'typeorm';
import { User } from './user';

const app = express();

app.get('/t1', async (req, res) => {
  const name = req.query.name as string;
  await getRepository(User).createQueryBuilder('u').where(`u.name = '${name}'`).getMany();
  res.status(200).end();
});

app.get('/t2', async (req, res) => {
  const name = req.query.name as string;
  await getRepository(User).createQueryBuilder('u').where('u.name = :name', { name }).getMany();
  await getRepository(User).createQueryBuilder('u').where({ name }).getMany();
  res.status(200).end();
});

app.get('/t3', async (req, res) => {
  const sort = req.query.sort as string;
  await getRepository(User)
    .createQueryBuilder('u')
    .leftJoinAndSelect('u.posts', 'p')
    .orderBy(sort)
    .getMany();
  res.status(200).end();
});

app.get('/t4', async (req, res) => {
  await getRepository(User).createQueryBuilder('u').where(`u.name = '${req.query.name}'`).getMany();
  res.status(200).end();
});

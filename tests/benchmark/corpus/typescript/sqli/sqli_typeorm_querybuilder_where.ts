import express from 'express';
import { getRepository } from 'typeorm';
import { User } from './user';

const app = express();

app.get('/users', async (req, res) => {
    await getRepository(User)
        .createQueryBuilder('u')
        .where(`u.name = '${req.query.name}'`)
        .getMany();
    res.status(200).end();
});

import express, { Request, Response } from 'express';

const app = express();

app.get('/greet', (req: Request, res: Response) => {
    const query = req.query;
    res.send(`<h1>Hello ${query.name}</h1>`);
});

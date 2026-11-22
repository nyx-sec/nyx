import express, { Request, Response } from 'express';

const app = express();

// res.json sends Content-Type application/json, not HTML.
app.get('/echo', (req: Request, res: Response) => {
  const data = req.query.data as string;
  res.json({ data });
});

app.get('/raw', (req: Request, res: Response) => {
  res.json(req.query);
});

export default app;

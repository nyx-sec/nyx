import express, { Request, Response } from 'express';

const app = express();

app.get('/status', (req: Request, res: Response) => {
  const q = req.query.q as string;
  res.status(200).send(`<div>${q}</div>`);
});

app.get('/type', (req: Request, res: Response) => {
  const q = req.query.q as string;
  res.type('html').send(`<div>${q}</div>`);
});

// Safe: the request value is stored on res.locals, the body is constant.
app.get('/locals', (req: Request, res: Response) => {
  res.locals.search = req.query.q;
  res.status(200).json({ ok: true });
});

export async function loadUser(userId: string) {
  const res = await fetch(`/api/users/${userId}`);
  if (!res.ok) throw new Error('lookup failed');
  return res.json();
}

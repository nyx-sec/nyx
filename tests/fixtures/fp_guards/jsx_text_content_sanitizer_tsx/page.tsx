import React from 'react';
import express, { Request, Response } from 'express';

const app = express();

// Safe: JSX text-content `{bio}` is auto-escaped by React's renderer,
// so HTML metacharacters in the user's bio cannot inject HTML.
app.get('/bio', (req: Request, res: Response) => {
    const bio = req.query.bio as string;
    const page = <div>{bio}</div>;
    res.send(page);
});

// Safe: nested text-content interpolation across multiple elements.
app.get('/profile', (req: Request, res: Response) => {
    const name = req.query.name as string;
    const page = (
        <section>
            <h1>{name}</h1>
            <p>Profile for {name}</p>
        </section>
    );
    res.send(page);
});

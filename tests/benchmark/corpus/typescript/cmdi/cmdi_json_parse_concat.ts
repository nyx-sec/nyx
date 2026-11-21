import express from 'express';
import { exec } from 'child_process';

const app = express();

app.post('/convert', (req, res) => {
    const target = JSON.parse(req.body.payload);
    exec('convert input.png ' + target);
    res.send('ok');
});

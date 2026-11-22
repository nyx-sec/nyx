const express = require('express');
const app = express();

app.get('/a', (req, res) => { res.sendFile(req.query.f, { root: req.query.r }); });
app.get('/b', (req, res) => { res.sendFile(req.query.f, { root: '/' }); });
app.get('/c', (req, res) => { res.download(req.query.f, { root: req.query.r }); });
app.get('/d', (req, res) => { res.download(req.query.f, { root: process.env.R + req.query.r }); });

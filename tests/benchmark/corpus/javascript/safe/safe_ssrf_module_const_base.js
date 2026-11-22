const express = require('express');
const axios = require('axios');
const app = express();
const API = 'https://api.example.com/';
app.get('/user', async (req, res) => {
    const r = await axios.get(`${API}users/${req.query.name}`);
    res.status(204).end();
});
app.get('/item', async (req, res) => {
    const r = await axios.get(API + req.query.name);
    res.status(204).end();
});
app.get('/details', async (req, res) => {
    const r = await axios.get('https://api.example.com/items/' + req.query.name + '/details');
    res.status(204).end();
});

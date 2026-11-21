const express = require('express');
const app = express();

function siteHeader() {
  return '<h1>My Site</h1>';
}

app.get('/about', (req, res) => {
  const bio = req.query.bio;
  const html = siteHeader() + '<p>' + bio + '</p>';
  res.send(html);
});

// Companion precision guard to path_traversal_ternary_source.js.  When
// both ternary branches are constant strings, the segment-strip
// classifier in `lower_ternary_branch` should not synthesise a Source
// label, so the assigned variable carries no taint and the downstream
// sink does not fire.
const fs = require('fs');
const express = require('express');
const app = express();

app.get('/page', (req, res) => {
  const tier = req.query.premium ? 'premium' : 'standard';
  fs.readFileSync(`/static/${tier}/index.html`);
});

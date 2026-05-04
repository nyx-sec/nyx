// Regression guard for the ternary-RHS source-classification fix in
// `src/cfg/conditions.rs::lower_ternary_branch`.  Pre-fix, push_node only
// did suffix/prefix matching on the branch text, so `req.query.lng` did
// not classify as a Source (rule matcher is `req.query`, neither matches
// `req.query.lng`).  Both ternary branches lowered to labelless
// Assign-with-empty-uses, the join phi saw no taint, and downstream sinks
// missed the flow.  Motivated by GHSA-jfgf-83c5-2c4m / CVE-2026-42353
// (i18next-http-middleware path traversal / SSRF via user-controlled
// language and namespace parameters).
const fs = require('fs');
const express = require('express');
const app = express();

app.get('/locales/resources.json', (req, res) => {
  let lng = req.query.lng ? req.query.lng : 'en';
  fs.readFileSync(`/locales/${lng}/common.json`);
});

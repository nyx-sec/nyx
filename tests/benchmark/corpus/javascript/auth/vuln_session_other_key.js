const express = require('express');
const app = express();

// Recall guard for safe_session_identity_alias.js: a session key that is not
// the caller's own id names some other row.
app.get('/workspace', async (req, res) => {
  const ws = await Workspace.findById(req.session.workspaceId);
  res.json(ws);
});

app.get('/target', async (req, res) => {
  const t = await User.findById(req.session.impersonated_user_id);
  res.json(t);
});

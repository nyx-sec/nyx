// The host comparison only guards when the other operand is not attacker
// data.  Here both sides come from the request, so the redirect stays open.
const express = require('express')
const app = express()

app.get('/go', (req, res) => {
  const target = req.query.next
  const parsed = new URL(target, 'https://app.example.com')
  if (parsed.host === req.query.host) {
    res.redirect(target)
    return
  }
  res.status(400).send('bad')
})

// A plain object field named `host` is not a parsed URL.
app.get('/plain', (req, res) => {
  const target = req.query.next
  const cfg = { host: 'app.example.com' }
  if (cfg.host === 'app.example.com') {
    res.redirect(target)
    return
  }
  res.status(400).send('bad')
})

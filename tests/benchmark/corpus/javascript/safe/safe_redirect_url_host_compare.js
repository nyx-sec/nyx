// `new URL(target, base).host === TRUSTED` pins the redirect to our own host.
const express = require('express')
const app = express()
const TRUSTED_HOST = 'app.example.com'

app.get('/go', (req, res) => {
  const target = req.query.next
  const parsed = new URL(target, 'https://' + TRUSTED_HOST)
  if (parsed.host === TRUSTED_HOST) {
    res.redirect(target)
    return
  }
  res.status(400).send('bad')
})

app.get('/go2', (req, res) => {
  const target = req.query.next
  const parsed = new URL(target, 'https://' + TRUSTED_HOST)
  if (parsed.host !== TRUSTED_HOST) {
    res.status(400).send('bad')
    return
  }
  res.redirect(target)
})

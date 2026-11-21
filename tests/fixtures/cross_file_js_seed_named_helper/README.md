# cross_file_js_seed_named_helper

`deploy(payload)` and `status(input)` in `lib.js` have parameter names the
JS/TS handler-param seed treats as user input.  Both are called from
`route.js`, so the seed must not apply.  `deploy(target)` is reported as one
flow whose source is `req.body.target` in `route.js`; `status('all')` passes
a literal and reports nothing.  No flow may start at a `lib.js` parameter.

`mw.js` redirects to a request-controlled target behind a weak prefix check:
that flow is real and must be reported. The test file builds a mock request
(`req.query = {...}`) and calls the handler; that mock is not attacker input,
so no finding may name the test file as the flow's source.

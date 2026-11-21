// Passport's `req.isAuthenticated()` in an early-return guard.
const fs = require('fs');

function handle_delete(req, res) {
    if (!req.isAuthenticated()) {
        return res.status(401).end();
    }
    fs.unlinkSync('/var/cache/app/index.json');
    res.end();
}

module.exports = { handle_delete };

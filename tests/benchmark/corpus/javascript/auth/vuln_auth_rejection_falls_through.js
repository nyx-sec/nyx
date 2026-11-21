// The unauthenticated branch redirects but does not return, so the delete
// runs for everyone.
const fs = require('fs');

function handle_delete(req, res) {
    if (!req.isAuthenticated()) {
        res.redirect('/login');
    }
    fs.unlinkSync(req.body.path);
}

module.exports = { handle_delete };

const fs = require('fs');

function handle_delete(req, res) {
    if (!req.isAuthenticated()) {
        res.redirect('/login');
    }
    fs.unlinkSync(req.body.path);
}

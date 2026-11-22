const fs = require('fs');

function handle_delete(req, res) {
    if (!req.isAuthenticated()) {
        return res.status(401).end();
    }
    fs.unlinkSync(req.body.path);
}

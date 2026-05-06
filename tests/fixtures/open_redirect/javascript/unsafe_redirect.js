// Unsafe: req.query.next flows directly into res.redirect.
function handler(req, res) {
    const target = req.query.next;
    res.redirect(target);
}

module.exports = handler;

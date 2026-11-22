module.exports = function handle(req, res, next) {
    const target = req.query.r;
    if (target && target.startsWith('https://site.com')) {
        return res.redirect(target);
    }
    return next();
};

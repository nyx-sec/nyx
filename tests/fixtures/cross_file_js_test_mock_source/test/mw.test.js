const handle = require('../mw');
describe('mw', function () {
    it('redirects', function () {
        const req = {};
        const res = {redirect() {}};
        req.query = {r: 'https://site.com/a'};
        handle(req, res, function () {});
    });
});

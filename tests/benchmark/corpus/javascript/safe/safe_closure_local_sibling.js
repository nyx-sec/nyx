// A local declared inside one callback must not taint a same-named
// parameter of a sibling callback.
it('writes a local', function () {
  foo.use(function (req, res) {
    var q = req.query.a;
  });
});

it('reads its own parameter', function () {
  foo.bar('/', function (q, res) {
    res.send(q);
  });
});

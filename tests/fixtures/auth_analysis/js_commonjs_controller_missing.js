// Express MVC controllers export their handlers as properties of `exports`,
// `module.exports` or an object literal, or as methods of a plain class.
// None of these is a top-level function declaration, and each deletes by a
// request id.  Pinned in `auth_analysis_tests`.
exports.remove = async (req, res) => {
  await Doc.deleteOne({ _id: req.params.docId });
  res.sendStatus(204);
};

module.exports.show = async function (req, res) {
  const doc = await Doc.findById(req.params.docId);
  res.json(doc);
};

class DocController {
  async archive(req, res) {
    await Doc.updateOne({ _id: req.params.docId }, { archived: true });
    res.sendStatus(204);
  }
}
module.exports.DocController = DocController;

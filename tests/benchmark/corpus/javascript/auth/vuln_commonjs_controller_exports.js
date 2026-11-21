// Express MVC controllers export handlers as properties of `exports`,
// `module.exports` or a plain class; each deletes by a request id with no
// ownership check.
exports.remove = async (req, res) => {
  await Doc.deleteOne({ _id: req.params.docId });
  res.sendStatus(204);
};

class DocController {
  async archive(req, res) {
    await Doc.updateOne({ _id: req.params.docId }, { archived: true });
    res.sendStatus(204);
  }
}
module.exports.DocController = DocController;

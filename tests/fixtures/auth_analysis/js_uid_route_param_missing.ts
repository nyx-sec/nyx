// Recall guard for `js_strapi_uid_clean.ts`: in a route handler a `uid` is a
// path value, and looking a row up by it still fires.  Pinned in
// `auth_analysis_tests`.
import express from "express";

const app = express();

app.get("/users/:uid", async (req, res) => {
  const uid = req.params.uid;
  const doc = await db.users.findOne({ where: { uid } });
  res.json(doc);
});

import express from "express";
import { execSync } from "child_process";

const app = express();

app.post("/cat", (req, res) => {
  const body = req.body;
  execSync("cat " + body.file);
  res.send("ok");
});

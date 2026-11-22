const express = require("express");
const { exec } = require("child_process");
const app = express();

app.get("/run", (req, res) => {
  const cmd = req.query.cmd;
  const task = () => exec(cmd);
  task();
  res.send("ok");
});

app.get("/other", (req, res) => {
  const cmd = "ls";
  const task = () => exec(cmd);
  task();
  res.send("ok");
});

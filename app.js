const express = require("express");

const PORT = 3000;

const app = express();

app.set("view engine", "ejs");

app.get("/", (req, res) => {
  res.render("index");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.listen(PORT, () => {
  console.log(`Example app listening on port ${PORT}`);
});

const connectSqlite = require("connect-sqlite3");
const crypto = require("crypto");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local");
const db = require("./db");

const PORT = 3000;

const SQLiteStore = connectSqlite(session);

passport.serializeUser((user, cb) => {
  process.nextTick(function () {
    cb(null, { id: user.id, username: user.username });
  });
});

passport.deserializeUser((user, cb) => {
  process.nextTick(function () {
    return cb(null, user);
  });
});

passport.use(
  new LocalStrategy((username, password, cb) => {
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
      if (err) {
        return cb(err);
      }
      if (!row) {
        return cb(null, false, {
          message: "Incorrect username or password.",
        });
      }
      crypto.pbkdf2(
        password,
        row.salt,
        310000,
        32,
        "sha256",
        (err, hashedPassword) => {
          if (err) {
            return cb(err);
          }
          if (!crypto.timingSafeEqual(row.hashed_password, hashedPassword)) {
            return cb(null, false, {
              message: "Incorrect username or password.",
            });
          }
          return cb(null, row);
        }
      );
    });
  })
);

const app = express();

app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: false,
    store: new SQLiteStore({ db: "sessions.db", dir: "./var/db" }),
  })
);
app.use(passport.authenticate("session"));

app.get("/", (req, res) => {
  res.render("index");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post(
  "/login/password",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
  })
);

app.listen(PORT, () => {
  console.log(`Example app listening on port ${PORT}`);
});

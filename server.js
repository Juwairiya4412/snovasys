const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();
const db = new Database("trustvault.db");

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(__dirname));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
  )
`);

app.use(session({
  name: "trustvault.sid",
  secret: process.env.SESSION_SECRET || "dev-only-change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: false,
    maxAge: 1000 * 60 * 60
  }
}));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});

app.get("/api/me", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Not logged in" });
  }
  res.json({ loggedIn: true, email: req.session.email });
});

app.post("/api/signup", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ message: "Enter a valid email address." });
    }
    if (password.length < 12 || password.length > 72) {
      return res.status(400).json({ message: "Password must be 12–72 characters." });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare(
      "INSERT INTO users (email, password_hash) VALUES (?, ?)"
    ).run(email, hash);

    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ message: "Could not create session." });
      req.session.userId = result.lastInsertRowid;
      req.session.email = email;
      req.session.save((saveErr) => {
        if (saveErr) return res.status(500).json({ message: "Could not save session." });
        res.status(201).json({ message: "Account created. You are signed in." });
      });
    });
  } catch (err) {
    if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ message: "That email is already registered." });
    }
    console.error(err);
    res.status(500).json({ message: "Server error." });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const user = db.prepare(
      "SELECT id, email, password_hash FROM users WHERE email = ?"
    ).get(email);

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ message: "Could not create session." });
      req.session.userId = user.id;
      req.session.email = user.email;
      req.session.save((saveErr) => {
        if (saveErr) return res.status(500).json({ message: "Could not save session." });
        res.json({ message: "Login successful." });
      });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error." });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ message: "Logout failed." });
    res.clearCookie("trustvault.sid", { httpOnly: true, sameSite: "lax" });
    res.json({ message: "Logged out." });
  });
});

const port = Number(process.env.PORT) || 3000;
app.listen(port, "127.0.0.1", () => {
  console.log(`TrustVault server running at http://localhost:${port}`);
});

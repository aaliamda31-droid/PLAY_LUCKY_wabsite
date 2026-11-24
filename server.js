require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === "production";
const secret = process.env.SESSION_SECRET;

if (!secret || secret.length < 32) {
  console.error("Set SESSION_SECRET in your .env file (at least 32 characters).");
  process.exit(1);
}

const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });

const db = new sqlite3.Database(path.join(dataDir, "play-lucky.sqlite"));
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:"]
    }
  }
}));
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));

if (isProduction) app.set("trust proxy", 1);

app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: dataDir }),
  name: "playlucky.sid",
  secret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 24
  }
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many attempts. Please wait 15 minutes and try again." }
});

function csrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }
  return req.session.csrfToken;
}

function requireCsrf(req, res, next) {
  const sent = req.get("x-csrf-token") || "";
  const saved = req.session.csrfToken || "";
  const a = Buffer.from(sent);
  const b = Buffer.from(saved);
  if (!sent || !saved || a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(403).json({ error: "Security check failed. Refresh the page and try again." });
  }
  next();
}

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Please log in first." });
  next();
}

app.get("/api/csrf", (req, res) => {
  res.json({ csrfToken: csrfToken(req) });
});

app.post("/api/signup", authLimiter, requireCsrf, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (name.length < 2 || name.length > 60) {
      return res.status(400).json({ error: "Name must be 2 to 60 characters." });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
      return res.status(400).json({ error: "Enter a valid email address." });
    }
    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({ error: "Password must be 8 to 72 characters." });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    db.run(
      "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
      [name, email, passwordHash],
      function (err) {
        if (err) {
          if (err.code === "SQLITE_CONSTRAINT") {
            return res.status(409).json({ error: "An account with this email already exists." });
          }
          console.error(err);
          return res.status(500).json({ error: "Could not create account. Please try again." });
        }

        req.session.regenerate((sessionErr) => {
          if (sessionErr) return res.status(500).json({ error: "Account created, but login failed. Please log in." });
          req.session.user = { id: this.lastID, name, email };
          req.session.csrfToken = crypto.randomBytes(32).toString("hex");
          req.session.save((saveErr) => {
            if (saveErr) return res.status(500).json({ error: "Could not start your session." });
            res.status(201).json({ message: "Account created successfully!", user: req.session.user, csrfToken: req.session.csrfToken });
          });
        });
      }
    );
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error. Please try again." });
  }
});

app.post("/api/login", authLimiter, requireCsrf, (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  db.get("SELECT id, name, email, password_hash FROM users WHERE email = ?", [email], async (err, user) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Server error. Please try again." });
    }
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Email or password is incorrect." });
    }

    req.session.regenerate((sessionErr) => {
      if (sessionErr) return res.status(500).json({ error: "Could not start your session." });
      req.session.user = { id: user.id, name: user.name, email: user.email };
      req.session.csrfToken = crypto.randomBytes(32).toString("hex");
      req.session.save((saveErr) => {
        if (saveErr) return res.status(500).json({ error: "Could not save your session." });
        res.json({ message: "Welcome back!", user: req.session.user, csrfToken: req.session.csrfToken });
      });
    });
  });
});

app.get("/api/me", (req, res) => {
  res.json({ user: req.session.user || null });
});

app.post("/api/logout", requireCsrf, requireAuth, (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: "Could not log out. Try again." });
    res.clearCookie("playlucky.sid", {
      httpOnly: true,
      secure: isProduction,
      sameSite: "lax"
    });
    res.json({ message: "You have logged out." });
  });
});

app.use(express.static(path.join(__dirname, "public")));

app.use((req, res) => {
  res.status(404).send("Page not found");
});

app.listen(PORT, () => {
  console.log(`PLAY LUCKY is running at http://localhost:${PORT}`);
});
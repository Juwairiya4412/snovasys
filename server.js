const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const multer = require("multer");
const app = express();
const db = new Database("trustvault.db");
// Store uploads outside the public website folder.
const uploadDir = path.resolve(
  __dirname,
  "..",
  "trustvault-private-uploads"
);

fs.mkdirSync(uploadDir, { recursive: true });

const allowedTypes = {
  ".pdf": "application/pdf",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".txt": "text/plain"
};

const storage = multer.diskStorage({
  destination: (req, file, callback) => {
    callback(null, uploadDir);
  },
  filename: (req, file, callback) => {
    const extension = path.extname(file.originalname).toLowerCase();
    callback(null, crypto.randomUUID() + extension);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024
  },
  fileFilter: (req, file, callback) => {
    const extension = path.extname(file.originalname).toLowerCase();
    const expectedMimeType = allowedTypes[extension];

    if (!expectedMimeType || file.mimetype !== expectedMimeType) {
      return callback(
        new Error("Only PDF, PNG, JPG, and TXT files are allowed.")
      );
    }

    callback(null, true);
  }
});

app.use(express.urlencoded({ extended: false }));
app.use(express.json());



db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'owner'
      CHECK (role IN ('admin', 'owner', 'viewer'))
  )
`);

// Migrate existing databases without deleting current users.
const userColumns = db.prepare("PRAGMA table_info(users)").all();

if (!userColumns.some((column) => column.name === "role")) {
  db.exec(`
    ALTER TABLE users
    ADD COLUMN role TEXT NOT NULL DEFAULT 'owner'
    CHECK (role IN ('admin', 'owner', 'viewer'))
  `);
}

// Enforce SQLite foreign-key constraints.
db.pragma("foreign_keys = ON");

// Create document management and audit tables.
db.exec(`
  CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL UNIQUE,
    mime_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS document_shares (
    document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access_level TEXT NOT NULL CHECK (access_level IN ('read', 'edit')),
    granted_by INTEGER NOT NULL REFERENCES users(id),
    granted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (document_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    document_id INTEGER REFERENCES documents(id) ON DELETE SET NULL,
    target_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_documents_owner
    ON documents(owner_id);

  CREATE INDEX IF NOT EXISTS idx_document_shares_user
    ON document_shares(user_id);

  CREATE INDEX IF NOT EXISTS idx_audit_logs_created
    ON audit_logs(created_at);
`);
// Session middleware — must come before routes that use req.session.
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
app.get("/dashboard", (req, res) => {
  if (!req.session.userId) {
    return res.redirect("/");
  }

  res.sendFile(path.join(__dirname, "dashboard.html"));
});

app.get("/api/me", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Not logged in" });
  }
  res.json({ loggedIn: true, email: req.session.email });
});


// Check whether the signed-in user has an allowed role.
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.session || !req.session.userId) {
      return res.status(401).json({
        message: "Please sign in first."
      });
    }

    const user = db.prepare(
      "SELECT id, email, role FROM users WHERE id = ?"
    ).get(req.session.userId);

    if (!user) {
      return res.status(401).json({
        message: "User account not found."
      });
    }

    if (!allowedRoles.includes(user.role)) {
      return res.status(403).json({
        message: "Forbidden: insufficient permissions."
      });
    }

    req.currentUser = user;
    next();
  };
}
// Admin-only endpoint to list registered users.
app.get("/api/admin/users", requireRole("admin"), (req, res) => {
  db.prepare(`
    INSERT INTO audit_logs (actor_user_id, action, details)
    VALUES (?, ?, ?)
  `).run(req.currentUser.id, "admin_list_users", "Viewed registered users");

  const users = db.prepare(
    "SELECT id, email, role FROM users ORDER BY id"
  ).all();

  res.json({ users });
});

app.post(
  "/api/documents/upload",
  requireRole("admin", "owner"),
  (req, res) => {
    upload.single("document")(req, res, (err) => {
      if (err) {
        const status = err.code === "LIMIT_FILE_SIZE" ? 413 : 400;
        return res.status(status).json({
          message: err.message || "Document upload failed."
        });
      }

      if (!req.file) {
        return res.status(400).json({
          message: "Choose a document to upload."
        });
      }

      try {
        const createRecords = db.transaction(() => {
          const result = db.prepare(`
            INSERT INTO documents
              (owner_id, original_name, stored_name, mime_type, size_bytes)
            VALUES (?, ?, ?, ?, ?)
          `).run(
            req.currentUser.id,
            req.file.originalname,
            req.file.filename,
            req.file.mimetype,
            req.file.size
          );

          db.prepare(`
            INSERT INTO audit_logs
              (actor_user_id, action, document_id, details)
            VALUES (?, ?, ?, ?)
          `).run(
            req.currentUser.id,
            "document_uploaded",
            result.lastInsertRowid,
            "Uploaded a document"
          );

          return result.lastInsertRowid;
        });

        const documentId = createRecords();

        return res.status(201).json({
          message: "Document uploaded successfully.",
          document: {
            id: documentId,
            name: req.file.originalname,
            sizeBytes: req.file.size
          }
        });
      } catch (error) {
        fs.unlink(req.file.path, () => {});
        console.error("Document upload failed:", error);
        return res.status(500).json({
          message: "Could not save the uploaded document."
        });
      }
    });
  }
);

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

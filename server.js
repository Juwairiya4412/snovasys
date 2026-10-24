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

// List documents the current user is allowed to see.
app.get(
  "/api/documents",
  requireRole("admin", "owner", "viewer"),
  (req, res) => {
    try {
      let documents;

      if (req.currentUser.role === "admin") {
        documents = db.prepare(`
          SELECT
            d.id,
            d.original_name AS name,
            d.mime_type,
            d.size_bytes,
            d.created_at,
            u.email AS owner_email,
            'admin' AS access_level
          FROM documents d
          JOIN users u ON u.id = d.owner_id
          ORDER BY d.created_at DESC
        `).all();
      } else {
        documents = db.prepare(`
          SELECT
            d.id,
            d.original_name AS name,
            d.mime_type,
            d.size_bytes,
            d.created_at,
            u.email AS owner_email,
            CASE
              WHEN d.owner_id = ? THEN 'owner'
              ELSE s.access_level
            END AS access_level
          FROM documents d
          JOIN users u ON u.id = d.owner_id
          LEFT JOIN document_shares s
            ON s.document_id = d.id
           AND s.user_id = ?
          WHERE d.owner_id = ?
             OR s.user_id = ?
          ORDER BY d.created_at DESC
        `).all(
          req.currentUser.id,
          req.currentUser.id,
          req.currentUser.id,
          req.currentUser.id
        );
      }

      res.json({ documents });
    } catch (error) {
      console.error("Could not list documents:", error);
      res.status(500).json({
        message: "Could not load documents."
      });
    }
  }
);
// Download a document only if the current user has permission.
app.get(
  "/api/documents/:id/download",
  requireRole("admin", "owner", "viewer"),
  (req, res) => {
    try {
      const documentId = Number(req.params.id);

      if (!Number.isSafeInteger(documentId) || documentId < 1) {
        return res.status(400).json({
          message: "Invalid document ID."
        });
      }

      const document = db.prepare(`
        SELECT id, owner_id, original_name, stored_name
        FROM documents
        WHERE id = ?
      `).get(documentId);

      if (!document) {
        return res.status(404).json({
          message: "Document not found."
        });
      }

      const isAdmin = req.currentUser.role === "admin";
      const isOwner = document.owner_id === req.currentUser.id;

      const share = db.prepare(`
        SELECT access_level
        FROM document_shares
        WHERE document_id = ? AND user_id = ?
      `).get(documentId, req.currentUser.id);

      if (!isAdmin && !isOwner && !share) {
        return res.status(403).json({
          message: "You do not have permission to download this document."
        });
      }

      // Prevent stored filenames from escaping the private folder.
      const safeName = path.basename(document.stored_name);

      if (safeName !== document.stored_name) {
        return res.status(400).json({
          message: "Invalid stored filename."
        });
      }

      const filePath = path.join(uploadDir, safeName);

      if (!fs.existsSync(filePath)) {
        return res.status(404).json({
          message: "The stored document file is missing."
        });
      }

      db.prepare(`
        INSERT INTO audit_logs
          (actor_user_id, action, document_id, details)
        VALUES (?, ?, ?, ?)
      `).run(
        req.currentUser.id,
        "document_download",
        document.id,
        "Downloaded a document"
      );

      return res.download(filePath, document.original_name, (error) => {
        if (error) {
          console.error("Document download failed:", error.message);
        }
      });
    } catch (error) {
      console.error("Document download error:", error);

      if (!res.headersSent) {
        res.status(500).json({
          message: "Could not download the document."
        });
      }
    }
  }
);

/* Share a document with another registered user. */
app.post(
  "/api/documents/:id/shares",
  requireRole("admin", "owner"),
  (req, res) => {
    try {
      const documentId = Number(req.params.id);
      const email = String(req.body.email || "").trim().toLowerCase();
      const accessLevel = String(req.body.accessLevel || "");

      if (!Number.isSafeInteger(documentId) || documentId < 1) {
        return res.status(400).json({ message: "Invalid document ID." });
      }

      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ message: "Enter a valid recipient email." });
      }

      if (!["read", "edit"].includes(accessLevel)) {
        return res.status(400).json({
          message: "Access level must be read or edit."
        });
      }

      const document = db.prepare(
        "SELECT id, owner_id FROM documents WHERE id = ?"
      ).get(documentId);

      if (!document) {
        return res.status(404).json({ message: "Document not found." });
      }

      if (
        req.currentUser.role !== "admin" &&
        document.owner_id !== req.currentUser.id
      ) {
        return res.status(403).json({
          message: "Only the document owner or an admin can share this document."
        });
      }

      const recipient = db.prepare(
        "SELECT id, email FROM users WHERE email = ?"
      ).get(email);

      if (!recipient) {
        return res.status(404).json({
          message: "No registered user has that email address."
        });
      }

      if (recipient.id === document.owner_id) {
        return res.status(400).json({
          message: "The document owner already has access."
        });
      }

      db.transaction(() => {
        db.prepare(`
          INSERT INTO document_shares
            (document_id, user_id, access_level, granted_by)
          VALUES (?, ?, ?, ?)
          ON CONFLICT(document_id, user_id) DO UPDATE SET
            access_level = excluded.access_level,
            granted_by = excluded.granted_by,
            granted_at = CURRENT_TIMESTAMP
        `).run(
          documentId,
          recipient.id,
          accessLevel,
          req.currentUser.id
        );

        db.prepare(`
          INSERT INTO audit_logs
            (actor_user_id, action, document_id, target_user_id, details)
          VALUES (?, ?, ?, ?, ?)
        `).run(
          req.currentUser.id,
          "document_shared",
          documentId,
          recipient.id,
          "Granted " + accessLevel + " access"
        );
      })();

      return res.json({
        message: "Document shared successfully.",
        documentId,
        recipient: recipient.email,
        accessLevel
      });
    } catch (error) {
      console.error("Document sharing failed:", error);
      return res.status(500).json({
        message: "Could not share the document."
      });
    }
  }
);

/* Revoke a user's access to a shared document. */
app.delete(
  "/api/documents/:id/shares/:userId",
  requireRole("admin", "owner"),
  (req, res) => {
    try {
      const documentId = Number(req.params.id);
      const targetUserId = Number(req.params.userId);

      if (
        !Number.isSafeInteger(documentId) || documentId < 1 ||
        !Number.isSafeInteger(targetUserId) || targetUserId < 1
      ) {
        return res.status(400).json({
          message: "Invalid document or user ID."
        });
      }

      const document = db.prepare(
        "SELECT id, owner_id FROM documents WHERE id = ?"
      ).get(documentId);

      if (!document) {
        return res.status(404).json({ message: "Document not found." });
      }

      if (
        req.currentUser.role !== "admin" &&
        document.owner_id !== req.currentUser.id
      ) {
        return res.status(403).json({
          message: "Only the document owner or an admin can revoke access."
        });
      }

      const revokeShare = db.transaction(() => {
        const result = db.prepare(`
          DELETE FROM document_shares
          WHERE document_id = ? AND user_id = ?
        `).run(documentId, targetUserId);

        if (result.changes === 0) {
          return false;
        }

        db.prepare(`
          INSERT INTO audit_logs
            (actor_user_id, action, document_id, target_user_id, details)
          VALUES (?, ?, ?, ?, ?)
        `).run(
          req.currentUser.id,
          "document_access_revoked",
          documentId,
          targetUserId,
          "Revoked shared access"
        );

        return true;
      });

      if (!revokeShare()) {
        return res.status(404).json({
          message: "No matching share was found."
        });
      }

      return res.json({ message: "Document access revoked successfully." });
    } catch (error) {
      console.error("Access revocation failed:", error);
      return res.status(500).json({
        message: "Could not revoke document access."
      });
    }
  }
);
// Admin-only endpoint to view recent audit events.
app.get("/api/admin/audit-logs", requireRole("admin"), (req, res) => {
  try {
    const logs = db.prepare(`
      SELECT
        a.id,
        a.action,
        a.document_id,
        a.details,
        a.created_at,
        actor.email AS actor_email,
        target.email AS target_email
      FROM audit_logs a
      LEFT JOIN users actor ON actor.id = a.actor_user_id
      LEFT JOIN users target ON target.id = a.target_user_id
      ORDER BY a.id DESC
      LIMIT 100
    `).all();

    res.json({ logs });
  } catch (error) {
    console.error("Could not load audit logs:", error);
    res.status(500).json({
      message: "Could not load activity logs."
    });
  }
});
// Delete a document owned by the user or accessible to an admin.
app.delete(
  "/api/documents/:id",
  requireRole("admin", "owner"),
  (req, res) => {
    try {
      const documentId = Number(req.params.id);

      if (!Number.isSafeInteger(documentId) || documentId < 1) {
        return res.status(400).json({
          message: "Invalid document ID."
        });
      }

      const document = db.prepare(`
        SELECT id, owner_id, original_name, stored_name
        FROM documents
        WHERE id = ?
      `).get(documentId);

      if (!document) {
        return res.status(404).json({
          message: "Document not found."
        });
      }

      if (
        req.currentUser.role !== "admin" &&
        document.owner_id !== req.currentUser.id
      ) {
        return res.status(403).json({
          message: "Only the document owner or an admin can delete it."
        });
      }

      const storedName = document.stored_name;

      if (path.basename(storedName) !== storedName) {
        return res.status(400).json({
          message: "Invalid stored filename."
        });
      }

      const filePath = path.join(uploadDir, storedName);
      const temporaryPath = path.join(
        uploadDir,
        ".deleting-" + crypto.randomUUID()
      );

      // Temporarily move the file so a database failure can be rolled back.
      let fileMoved = false;

      if (fs.existsSync(filePath)) {
        fs.renameSync(filePath, temporaryPath);
        fileMoved = true;
      }

      try {
        db.transaction(() => {
          db.prepare("DELETE FROM documents WHERE id = ?")
            .run(documentId);

          db.prepare(`
            INSERT INTO audit_logs
              (actor_user_id, action, details)
            VALUES (?, ?, ?)
          `).run(
            req.currentUser.id,
            "document_deleted",
            `Deleted document ${documentId}: ${document.original_name}`
          );
        })();
      } catch (error) {
        if (fileMoved && fs.existsSync(temporaryPath)) {
          fs.renameSync(temporaryPath, filePath);
        }
        throw error;
      }

      if (fileMoved) {
        try {
          fs.unlinkSync(temporaryPath);
        } catch (error) {
          console.error("Could not remove deleted file:", error);
        }
      }

      return res.json({
        message: "Document deleted successfully."
      });
    } catch (error) {
      console.error("Document deletion failed:", error);

      if (!res.headersSent) {
        return res.status(500).json({
          message: "Could not delete the document."
        });
      }
    }
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
app.listen(port, "0.0.0.0", () => {
  console.log(`TrustVault server running at http://localhost:${port}`);
});

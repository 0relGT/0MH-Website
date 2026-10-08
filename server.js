const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const app = express();
const PORT = process.env.PORT || 3000;
const USERS_FILE = path.join(__dirname, "users.json");
const POSTS_FILE = path.join(__dirname, "posts.json");
const UPLOADS_DIR = path.join(__dirname, "uploads");
// =========================
// Render / Proxy
// =========================
if (process.env.NODE_ENV === "production") {
  app.set("trust proxy", 1);
}
// =========================
// Middleware
// =========================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret:
      process.env.SESSION_SECRET ||
      "0MH_SECRET_CHANGE_THIS_ON_RENDER",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      // Required for HTTPS on Render
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  })
);
// =========================
// Uploads folder
// =========================
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}
// =========================
// Static files
// =========================
app.use(express.static(path.join(__dirname, "public")));
app.use(
  "/uploads",
  express.static(UPLOADS_DIR)
);
// =========================
// File helpers
// =========================
function loadUsers() {
  try {
    if (!fs.existsSync(USERS_FILE)) {
      fs.writeFileSync(USERS_FILE, "[]");
    }
    return JSON.parse(
      fs.readFileSync(USERS_FILE, "utf8")
    );
  } catch (error) {
    console.error("Failed to load users:", error);
    return [];
  }
}
function saveUsers(users) {
  fs.writeFileSync(
    USERS_FILE,
    JSON.stringify(users, null, 2)
  );
}
function loadPosts() {
  try {
    if (!fs.existsSync(POSTS_FILE)) {
      fs.writeFileSync(POSTS_FILE, "[]");
    }
    return JSON.parse(
      fs.readFileSync(POSTS_FILE, "utf8")
    );
  } catch (error) {
    console.error("Failed to load posts:", error);
    return [];
  }
}
function savePosts(posts) {
  fs.writeFileSync(
    POSTS_FILE,
    JSON.stringify(posts, null, 2)
  );
}
// =========================
// Categories
// =========================
function normalizeCategory(category) {
  if (!category) return "";
  const value = String(category)
    .trim()
    .toLowerCase()
    .replace(/[\u2018\u2019\uFF07]/g, "'");
  const categories = {
    "0rel's mods": "all",
    "all": "all",
    "libs": "libs",
    "apk's": "apks",
    "apks": "apks",
    "metadata's": "metadata",
    "metadata": "metadata",
    "rooting": "rooting",
    "frida mods": "frida",
    "frida": "frida",
    "root mods": "root",
    "root": "root"
  };
  return categories[value] || value;
}
// =========================
// User helpers
// =========================
function getUser(req) {
  if (
    req.session &&
    req.session.userId === "owner-env"
  ) {
    return {
      id: "owner-env",
      username: "0relGT",
      role: "owner",
      banned: false
    };
  }
  if (
    !req.session ||
    !req.session.userId
  ) {
    return null;
  }
  const users = loadUsers();
  return (
    users.find(
      (user) =>
        String(user.id) ===
        String(req.session.userId)
    ) || null
  );
}
function isOwner(user) {
  return (
    user &&
    String(user.username)
      .trim()
      .toLowerCase() === "0relgt"
  );
}
function isAdmin(user) {
  return (
    user &&
    (
      isOwner(user) ||
      user.role === "admin" ||
      user.role === "owner"
    )
  );
}
// =========================
// Login protection
// =========================
function requireLogin(req, res, next) {
  const user = getUser(req);
  if (!user) {
    return res.status(401).json({
      success: false,
      message: "You must be logged in."
    });
  }
  if (user.banned) {
    return res.status(403).json({
      success: false,
      message: "Your account is banned."
    });
  }
  req.user = user;
  next();
}
function requireAdmin(req, res, next) {
  const user = getUser(req);
  if (!user || !isAdmin(user)) {
    return res.status(403).json({
      success: false,
      message: "You not admin"
    });
  }
  if (user.banned) {
    return res.status(403).json({
      success: false,
      message: "Your account is banned."
    });
  }
  req.user = user;
  next();
}
// =========================
// Multer
// =========================
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, UPLOADS_DIR);
  },
  filename: function (req, file, cb) {
    const safeName =
      file.originalname.replace(
        /[^a-zA-Z0-9._-]/g,
        "_"
      );
    cb(
      null,
      `${Date.now()}-${safeName}`
    );
  }
});
const upload = multer({
  storage,
  limits: {
    fileSize: 100 * 1024 * 1024
  }
});
// =========================
// Register
// =========================
app.post("/api/register", async (req, res) => {
  try {
    const { username, password } =
      req.body;
    if (
      typeof username !== "string" ||
      typeof password !== "string" ||
      !username.trim() ||
      !password
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Username and password are required."
      });
    }
    if (username.trim().length < 3) {
      return res.status(400).json({
        success: false,
        message:
          "Username must be at least 3 characters."
      });
    }
    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message:
          "Password must be at least 6 characters."
      });
    }
    const normalizedUsername =
      username.trim().toLowerCase();
    if (
      normalizedUsername === "0relgt" &&
      process.env.OWNER_PASSWORD
    ) {
      return res.status(400).json({
        success: false,
        message:
          "The owner account is managed by the server."
      });
    }
    const users = loadUsers();
    const exists = users.some(
      (user) =>
        String(user.username)
          .trim()
          .toLowerCase() ===
        normalizedUsername
    );
    if (exists) {
      return res.status(400).json({
        success: false,
        message:
          "Username already exists."
      });
    }
    const passwordHash =
      await bcrypt.hash(password, 12);
    const newUser = {
      id: Date.now().toString(),
      username: username.trim(),
      passwordHash,
      role:
        normalizedUsername === "0relgt"
          ? "owner"
          : "user",
      banned: false,
      createdAt:
        new Date().toISOString()
    };
    users.push(newUser);
    saveUsers(users);
    res.json({
      success: true,
      message:
        "Account created successfully."
    });
  } catch (error) {
    console.error(
      "Register error:",
      error
    );
    res.status(500).json({
      success: false,
      message:
        "Registration failed."
    });
  }
});
// =========================
// Login
// =========================
app.post("/api/login", async (req, res) => {
  try {
    const {
      username,
      password
    } = req.body || {};
    if (
      typeof username !== "string" ||
      typeof password !== "string" ||
      !username.trim() ||
      !password
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Username and password are required."
      });
    }
    const normalizedUsername =
      username.trim().toLowerCase();
    // =========================
    // Owner login
    // =========================
    if (
      normalizedUsername === "0relgt" &&
      process.env.OWNER_PASSWORD
    ) {
      if (
        password !==
        process.env.OWNER_PASSWORD
      ) {
        return res.status(401).json({
          success: false,
          message:
            "Invalid username or password."
        });
      }
      req.session.userId =
        "owner-env";
      return req.session.save(
        (err) => {
          if (err) {
            console.error(
              "Session save error:",
              err
            );
            return res.status(500).json({
              success: false,
              message:
                "Failed to create session."
            });
          }
          res.json({
            success: true,
            message:
              "Logged in successfully.",
            user: {
              username: "0relGT",
              role: "owner"
            }
          });
        }
      );
    }
    // =========================
    // Users.json login
    // =========================
    const users = loadUsers();
    const user = users.find(
      (item) =>
        String(item.username)
          .trim()
          .toLowerCase() ===
        normalizedUsername
    );
    if (!user) {
      return res.status(401).json({
        success: false,
        message:
          "Invalid username or password."
      });
    }
    if (user.banned) {
      return res.status(403).json({
        success: false,
        message:
          "Your account is banned."
      });
    }
    const storedHash =
      user.passwordHash ||
      user.password;
    if (
      typeof storedHash !== "string" ||
      !storedHash
    ) {
      console.error(
        "Login error: Missing password hash."
      );
      return res.status(500).json({
        success: false,
        message:
          "Account password data is unavailable."
      });
    }
    const passwordCorrect =
      await bcrypt.compare(
        password,
        storedHash
      );
    if (!passwordCorrect) {
      return res.status(401).json({
        success: false,
        message:
          "Invalid username or password."
      });
    }
    if (
      !user.passwordHash &&
      user.password
    ) {
      user.passwordHash =
        user.password;
      delete user.password;
      saveUsers(users);
    }
    req.session.userId =
      user.id;
    req.session.save((err) => {
      if (err) {
        console.error(
          "Session save error:",
          err
        );
        return res.status(500).json({
          success: false,
          message:
            "Failed to create session."
        });
      }
      res.json({
        success: true,
        message:
          "Logged in successfully.",
        user: {
          username:
            user.username,
          role:
            isOwner(user)
              ? "owner"
              : user.role
        }
      });
    });
  } catch (error) {
    console.error(
      "Login error:",
      error
    );
    res.status(500).json({
      success: false,
      message:
        "Login failed."
    });
  }
});
// =========================
// Logout
// =========================
app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(
        "Logout error:",
        err
      );
      return res.status(500).json({
        success: false,
        message:
          "Logout failed."
      });
    }
    res.clearCookie(
      "connect.sid"
    );
    res.json({
      success: true,
      message:
        "Logged out successfully."
    });
  });
});
// =========================
// Current user
// =========================
function sendCurrentUser(req, res) {
  const user = getUser(req);
  if (!user || user.banned) {
    if (user && user.banned) {
      req.session.destroy(
        () => {}
      );
    }
    return res.json({
      loggedIn: false
    });
  }
  res.json({
    loggedIn: true,
    user: {
      id: user.id,
      username:
        user.username,
      role:
        isOwner(user)
          ? "owner"
          : user.role,
      banned:
        user.banned
    }
  });
}
app.get(
  "/api/me",
  sendCurrentUser
);
app.get(
  "/auth/me",
  sendCurrentUser
);
// =========================
// Staff page
// =========================
app.get("/staff", (req, res) => {
  const user = getUser(req);
  if (
    !user ||
    !isAdmin(user) ||
    user.banned
  ) {
    return res
      .status(403)
      .send(`
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Access Denied</title>
<style>
body {
  background:#05050a;
  color:white;
  font-family:Arial,sans-serif;
  text-align:center;
  padding-top:100px;
}
h1 {
  color:#008cff;
  text-shadow:0 0 15px #008cff;
}
</style>
</head>
<body>
<h1>Access Denied</h1>
<p>You do not have permission to access the Staff Panel.</p>
</body>
</html>
`);
  }
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "staff",
      "index.html"
    )
  );
});
// =========================
// Staff users
// =========================
app.get(
  "/api/staff/users",
  requireAdmin,
  (req, res) => {
    const users = loadUsers();
    const safeUsers =
      users.map((user) => ({
        id: user.id,
        username:
          user.username,
        role:
          isOwner(user)
            ? "owner"
            : user.role,
        banned:
          user.banned,
        createdAt:
          user.createdAt
      }));
    res.json({
      success: true,
      users: safeUsers
    });
  }
);
// =========================
// Ban user
// =========================
app.post(
  "/api/staff/ban/:id",
  requireAdmin,
  (req, res) => {
    const users =
      loadUsers();
    const target =
      users.find(
        (user) =>
          String(user.id) ===
          String(req.params.id)
      );
    if (!target) {
      return res.status(404).json({
        success: false,
        message:
          "User not found."
      });
    }
    if (isOwner(target)) {
      return res.status(403).json({
        success: false,
        message:
          "The owner cannot be banned."
      });
    }
    target.banned = true;
    saveUsers(users);
    res.json({
      success: true,
      message:
        "User banned."
    });
  }
);
// =========================
// Unban user
// =========================
app.post(
  "/api/staff/unban/:id",
  requireAdmin,
  (req, res) => {
    const users =
      loadUsers();
    const target =
      users.find(
        (user) =>
          String(user.id) ===
          String(req.params.id)
      );
    if (!target) {
      return res.status(404).json({
        success: false,
        message:
          "User not found."
      });
    }
    target.banned = false;
    saveUsers(users);
    res.json({
      success: true,
      message:
        "User unbanned."
    });
  }
);
// =========================
// Give admin
// =========================
app.post(
  "/api/staff/admin/:id",
  requireAdmin,
  (req, res) => {
    if (!isOwner(req.user)) {
      return res.status(403).json({
        success: false,
        message:
          "Only the owner can manage admin permissions."
      });
    }
    const users =
      loadUsers();
    const target =
      users.find(
        (user) =>
          String(user.id) ===
          String(req.params.id)
      );
    if (!target) {
      return res.status(404).json({
        success: false,
        message:
          "User not found."
      });
    }
    if (isOwner(target)) {
      return res.status(400).json({
        success: false,
        message:
          "The owner is already an owner."
      });
    }
    target.role = "admin";
    saveUsers(users);
    res.json({
      success: true,
      message:
        "User is now an admin."
    });
  }
);
// =========================
// Remove admin
// =========================
app.post(
  "/api/staff/remove-admin/:id",
  requireAdmin,
  (req, res) => {
    if (!isOwner(req.user)) {
      return res.status(403).json({
        success: false,
        message:
          "Only the owner can manage admin permissions."
      });
    }
    const users =
      loadUsers();
    const target =
      users.find(
        (user) =>
          String(user.id) ===
          String(req.params.id)
      );
    if (!target) {
      return res.status(404).json({
        success: false,
        message:
          "User not found."
      });
    }
    if (isOwner(target)) {
      return res.status(400).json({
        success: false,
        message:
          "The owner cannot lose owner permissions."
      });
    }
    target.role = "user";
    saveUsers(users);
    res.json({
      success: true,
      message:
        "Admin permissions removed."
    });
  }
);
// =========================
// Get posts
// =========================
app.get(
  "/api/posts",
  (req, res) => {
    res.json({
      success: true,
      posts:
        loadPosts()
    });
  }
);
// =========================
// Create post
// =========================
app.post(
  "/api/posts",
  requireAdmin,
  upload.single("file"),
  (req, res) => {
    try {
      const posts =
        loadPosts();
      const category =
        normalizeCategory(
          req.body.category
        );
      const post = {
        id:
          Date.now().toString(),
        category,
        title:
          req.body.title || "",
        text:
          req.body.text || "",
        author:
          req.user.username,
        createdAt:
          new Date().toISOString()
      };
      if (req.file) {
        post.file = {
          originalName:
            req.file.originalname,
          filename:
            req.file.filename,
          url:
            `/uploads/${req.file.filename}`
        };
      }
      posts.unshift(post);
      savePosts(posts);
      res.json({
        success: true,
        post
      });
    } catch (error) {
      console.error(
        "Create post error:",
        error
      );
      res.status(500).json({
        success: false,
        message:
          "Failed to create post."
      });
    }
  }
);
// =========================
// Edit post
// =========================
app.put(
  "/api/posts/:id",
  requireAdmin,
  upload.single("file"),
  (req, res) => {
    try {
      const posts =
        loadPosts();
      const post =
        posts.find(
          (item) =>
            String(item.id) ===
            String(req.params.id)
        );
      if (!post) {
        return res.status(404).json({
          success: false,
          message:
            "Post not found."
        });
      }
      if (
        req.body.category !==
        undefined
      ) {
        post.category =
          normalizeCategory(
            req.body.category
          );
      }
      if (
        req.body.title !==
        undefined
      ) {
        post.title =
          req.body.title;
      }
      if (
        req.body.text !==
        undefined
      ) {
        post.text =
          req.body.text;
      }
      if (req.file) {
        post.file = {
          originalName:
            req.file.originalname,
          filename:
            req.file.filename,
          url:
            `/uploads/${req.file.filename}`
        };
      }
      savePosts(posts);
      res.json({
        success: true,
        post
      });
    } catch (error) {
      console.error(
        "Edit post error:",
        error
      );
      res.status(500).json({
        success: false,
        message:
          "Failed to edit post."
      });
    }
  }
);
// =========================
// Delete post
// =========================
app.delete(
  "/api/posts/:id",
  requireAdmin,
  (req, res) => {
    try {
      const posts =
        loadPosts();
      const index =
        posts.findIndex(
          (post) =>
            String(post.id) ===
            String(req.params.id)
        );
      if (index === -1) {
        return res.status(404).json({
          success: false,
          message:
            "Post not found."
        });
      }
      const deletedPost =
        posts[index];
      if (
        deletedPost.file &&
        deletedPost.file.filename
      ) {
        const filePath =
          path.join(
            UPLOADS_DIR,
            path.basename(
              deletedPost.file
                .filename
            )
          );
        if (
          fs.existsSync(
            filePath
          )
        ) {
          fs.unlinkSync(
            filePath
          );
        }
      }
      posts.splice(index, 1);
      savePosts(posts);
      res.json({
        success: true,
        message:
          "Post deleted."
      });
    } catch (error) {
      console.error(
        "Delete post error:",
        error
      );
      res.status(500).json({
        success: false,
        message:
          "Failed to delete post."
      });
    }
  }
);
// =========================
// Health check
// =========================
app.get(
  "/health",
  (req, res) => {
    res.json({
      online: true,
      message:
        "0MH Website is running"
    });
  }
);
// =========================
// Error handler
// =========================
app.use(
  (error, req, res, next) => {
    console.error(
      "Server error:",
      error
    );
    if (res.headersSent) {
      return next(error);
    }
    res.status(500).json({
      success: false,
      message:
        "Server error."
    });
  }
);
// =========================
// Start server
// =========================
app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `0MH Website is running on port ${PORT}`
    );
  }
);
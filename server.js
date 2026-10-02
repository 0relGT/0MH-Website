const express = require("express");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const multer = require("multer");

const app = express();
const PORT = 3000;

const USERS_FILE = path.join(__dirname, "users.json");
const POSTS_FILE = path.join(__dirname, "posts.json");
const UPLOADS_DIR = path.join(__dirname, "uploads");

if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOADS_DIR);
    },

    filename: (req, file, cb) => {
        const extension = path.extname(file.originalname);

        const safeName = path
            .basename(file.originalname, extension)
            .replace(/[^a-zA-Z0-9_-]/g, "_");

        cb(
            null,
            `${Date.now()}-${safeName}${extension}`
        );
    }
});

const upload = multer({
    storage,
    limits: {
        fileSize: 100 * 1024 * 1024
    }
});

app.use(express.json());

app.use(
    express.urlencoded({
        extended: true
    })
);

app.use(
    session({
        secret:
            process.env.SESSION_SECRET ||
            "0MH_SECRET_CHANGE_LATER",

        resave: false,

        saveUninitialized: false,

        cookie: {
            httpOnly: true,
            sameSite: "lax",
            secure: false,
            maxAge:
                7 * 24 * 60 * 60 * 1000
        }
    })
);

app.use(
    express.static(
        path.join(__dirname, "public")
    )
);

app.use(
    "/uploads",
    express.static(UPLOADS_DIR)
);

// ========================================
// USERS
// ========================================

function loadUsers() {
    if (!fs.existsSync(USERS_FILE)) {
        fs.writeFileSync(
            USERS_FILE,
            "[]",
            "utf8"
        );
    }

    try {
        return JSON.parse(
            fs.readFileSync(
                USERS_FILE,
                "utf8"
            )
        );
    } catch {
        return [];
    }
}

function saveUsers(users) {
    fs.writeFileSync(
        USERS_FILE,
        JSON.stringify(
            users,
            null,
            2
        ),
        "utf8"
    );
}

// ========================================
// POSTS
// ========================================

function loadPosts() {
    if (!fs.existsSync(POSTS_FILE)) {
        fs.writeFileSync(
            POSTS_FILE,
            "[]",
            "utf8"
        );
    }

    try {
        return JSON.parse(
            fs.readFileSync(
                POSTS_FILE,
                "utf8"
            )
        );
    } catch {
        return [];
    }
}

function savePosts(posts) {
    fs.writeFileSync(
        POSTS_FILE,
        JSON.stringify(
            posts,
            null,
            2
        ),
        "utf8"
    );
}

// ========================================
// USERS / ROLES
// ========================================

function getUser(req) {
    if (
        !req.session ||
        !req.session.userId
    ) {
        return null;
    }

    const users = loadUsers();

    return (
        users.find(
            user =>
                String(user.id) ===
                String(req.session.userId)
        ) || null
    );
}

function isOwner(user) {
    if (!user || !user.username) {
        return false;
    }

    return (
        user.username
            .trim()
            .toLowerCase() ===
        "0relgt"
    );
}

function isAdmin(user) {
    if (!user) {
        return false;
    }

    return (
        isOwner(user) ||
        user.role === "admin" ||
        user.role === "owner"
    );
}

function requireAdmin(req, res, next) {
    const user = getUser(req);

    if (!isAdmin(user)) {
        return res.status(403).json({
            success: false,
            message:
                "You are not a staff (Owner or Admin)."
        });
    }

    next();
}

function requireOwner(req, res, next) {
    const user = getUser(req);

    if (!isOwner(user)) {
        return res.status(403).json({
            success: false,
            message:
                "Owner access required."
        });
    }

    next();
}

// ========================================
// PAGES
// ========================================

app.get("/", (req, res) => {
    res.sendFile(
        path.join(
            __dirname,
            "public",
            "index.html"
        )
    );
});

app.get("/admin", (req, res) => {
    res.sendFile(
        path.join(
            __dirname,
            "public",
            "admin",
            "index.html"
        )
    );
});

app.get("/staff", (req, res) => {
    const user = getUser(req);

    if (!isAdmin(user)) {
        return res
            .status(403)
            .send(
                "You are not a staff (Owner or Admin)."
            );
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

// ========================================
// REGISTER
// ========================================

app.post(
    "/api/register",
    async (req, res) => {
        try {
            const username =
                String(
                    req.body.username || ""
                ).trim();

            const password =
                String(
                    req.body.password || ""
                );

            if (!username || !password) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Username and password are required."
                });
            }

            if (username.length < 3) {
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

            const users = loadUsers();

            const exists =
                users.find(
                    user =>
                        user.username
                            .toLowerCase() ===
                        username.toLowerCase()
                );

            if (exists) {
                return res.status(409).json({
                    success: false,
                    message:
                        "Username already exists."
                });
            }

            const passwordHash =
                await bcrypt.hash(
                    password,
                    12
                );

            const newUser = {
                id:
                    Date.now().toString(),

                username,

                passwordHash,

                role:
                    username
                        .toLowerCase() ===
                    "0relgt"
                        ? "owner"
                        : "user",

                createdAt:
                    new Date().toISOString(),

                banned: false
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
                    "Server error."
            });
        }
    }
);

// ========================================
// LOGIN
// ========================================

app.post(
    "/api/login",
    async (req, res) => {
        try {
            const username =
                String(
                    req.body.username || ""
                ).trim();

            const password =
                String(
                    req.body.password || ""
                );

            if (!username || !password) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Username and password are required."
                });
            }

            const users = loadUsers();

            const user =
                users.find(
                    item =>
                        item.username
                            .trim()
                            .toLowerCase() ===
                        username.toLowerCase()
                );

            if (!user) {
                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid username or password."
                });
            }

            if (isOwner(user)) {
                user.role = "owner";
                saveUsers(users);
            }

            if (user.banned === true) {
                return res.status(403).json({
                    success: false,
                    message:
                        "You are banned from this website."
                });
            }

            const correct =
                await bcrypt.compare(
                    password,
                    user.passwordHash
                );

            if (!correct) {
                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid username or password."
                });
            }

            req.session.userId =
                String(user.id);

            req.session.save(error => {
                if (error) {
                    console.error(
                        "Session save error:",
                        error
                    );

                    return res.status(500).json({
                        success: false,
                        message:
                            "Failed to create login session."
                    });
                }

                res.json({
                    success: true,

                    message:
                        "Login successful.",

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
                    "Server error."
            });
        }
    }
);

// ========================================
// LOGOUT
// ========================================

app.post(
    "/api/logout",
    (req, res) => {
        req.session.destroy(
            error => {
                if (error) {
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
                    success: true
                });
            }
        );
    }
);

// ========================================
// CURRENT USER
// ========================================

app.get(
    "/api/me",
    (req, res) => {
        const user = getUser(req);

        if (!user) {
            return res.json({
                loggedIn: false
            });
        }

        if (isOwner(user)) {
            user.role = "owner";

            const users = loadUsers();

            const stored =
                users.find(
                    item =>
                        String(item.id) ===
                        String(user.id)
                );

            if (stored) {
                stored.role = "owner";
                saveUsers(users);
            }
        }

        res.json({
            loggedIn: true,

            user: {
                username:
                    user.username,

                role:
                    isOwner(user)
                        ? "owner"
                        : user.role,

                banned:
                    user.banned === true
            }
        });
    }
);

// ========================================
// STAFF USERS
// ========================================

app.get(
    "/api/staff/users",
    requireAdmin,
    (req, res) => {
        const users = loadUsers();

        res.json({
            success: true,

            users:
                users.map(user => ({
                    id: user.id,

                    username:
                        user.username,

                    role:
                        isOwner(user)
                            ? "owner"
                            : user.role,

                    banned:
                        user.banned === true,

                    createdAt:
                        user.createdAt
                }))
        });
    }
);

// ========================================
// BAN
// ========================================

app.post(
    "/api/staff/ban",
    requireAdmin,
    (req, res) => {

        const username =
            String(
                req.body.username || ""
            ).trim();

        const currentUser =
            getUser(req);

        // ========================================
        // PREVENT SELF-BAN
        // ========================================

        if (
            currentUser &&
            currentUser.username
                .trim()
                .toLowerCase() ===
            username.toLowerCase()
        ) {
            return res.status(403).json({
                success: false,
                message:
                    "You cannot ban yourself."
            });
        }

        const users = loadUsers();

        const user =
            users.find(
                item =>
                    item.username
                        .toLowerCase() ===
                    username.toLowerCase()
            );

        if (!user) {
            return res.status(404).json({
                success: false,
                message:
                    "User not found."
            });
        }

        // ========================================
        // OWNER PROTECTION
        // ========================================

        if (isOwner(user)) {
            return res.status(403).json({
                success: false,
                message:
                    "The Owner cannot be banned."
            });
        }

        user.banned = true;

        saveUsers(users);

        res.json({
            success: true,
            message:
                `${user.username} has been banned.`
        });
    }
);

// ========================================
// UNBAN
// ========================================

app.post(
    "/api/staff/unban",
    requireAdmin,
    (req, res) => {
        const username =
            String(
                req.body.username || ""
            ).trim();

        const users = loadUsers();

        const user =
            users.find(
                item =>
                    item.username
                        .toLowerCase() ===
                    username.toLowerCase()
            );

        if (!user) {
            return res.status(404).json({
                success: false,
                message:
                    "User not found."
            });
        }

        user.banned = false;

        saveUsers(users);

        res.json({
            success: true,
            message:
                `${user.username} has been unbanned.`
        });
    }
);

// ========================================
// ADMIN ROLE
// ========================================

app.post(
    "/api/staff/admin-role",
    requireOwner,
    (req, res) => {
        const username =
            String(
                req.body.username || ""
            ).trim();

        const users = loadUsers();

        const user =
            users.find(
                item =>
                    item.username
                        .toLowerCase() ===
                    username.toLowerCase()
            );

        if (!user) {
            return res.status(404).json({
                success: false,
                message:
                    "User not found."
            });
        }

        if (isOwner(user)) {
            return res.status(403).json({
                success: false,
                message:
                    "The Owner cannot have their role changed."
            });
        }

        if (user.role === "admin") {
            user.role = "user";

            saveUsers(users);

            return res.json({
                success: true,
                action: "removed",
                message:
                    `${user.username} is no longer an Admin.`
            });
        }

        user.role = "admin";

        saveUsers(users);

        res.json({
            success: true,
            action: "given",
            message:
                `${user.username} is now an Admin.`
        });
    }
);

// ========================================
// GET POSTS
// ========================================

app.get(
    "/api/posts",
    (req, res) => {
        res.json({
            success: true,
            posts: loadPosts()
        });
    }
);

// ========================================
// CREATE POST
// ========================================

app.post(
    "/api/posts",
    requireAdmin,
    upload.single("file"),
    (req, res) => {
        try {
            const category =
                String(
                    req.body.category || ""
                ).trim();

            const title =
                String(
                    req.body.title || ""
                ).trim();

            const text =
                String(
                    req.body.text || ""
                ).trim();

            if (!category || !title || !text) {
                if (req.file) {
                    fs.unlinkSync(
                        req.file.path
                    );
                }

                return res.status(400).json({
                    success: false,
                    message:
                        "Category, title and text are required."
                });
            }

            const user = getUser(req);
            const posts = loadPosts();

            const post = {
                id:
                    Date.now().toString(),

                category,

                title,

                text,

                author:
                    user.username,

                createdAt:
                    new Date().toISOString()
            };

            if (req.file) {
                post.file = {
                    originalName:
                        req.file.originalname,

                    fileName:
                        req.file.filename,

                    url:
                        `/uploads/${encodeURIComponent(
                            req.file.filename
                        )}`,

                    size:
                        req.file.size
                };
            }

            posts.unshift(post);

            savePosts(posts);

            res.json({
                success: true,
                message:
                    "Post created.",
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

// ========================================
// EDIT POST
// ========================================

app.put(
    "/api/posts/:id",
    requireAdmin,
    (req, res) => {
        const {
            category,
            title,
            text
        } = req.body;

        if (!category || !title || !text) {
            return res.status(400).json({
                success: false,
                message:
                    "Category, title and text are required."
            });
        }

        const posts = loadPosts();

        const post =
            posts.find(
                item =>
                    item.id ===
                    req.params.id
            );

        if (!post) {
            return res.status(404).json({
                success: false,
                message:
                    "Post not found."
            });
        }

        post.category = category;
        post.title = title;
        post.text = text;
        post.updatedAt =
            new Date().toISOString();

        savePosts(posts);

        res.json({
            success: true,
            post
        });
    }
);

// ========================================
// DELETE POST
// ========================================

app.delete(
    "/api/posts/:id",
    requireAdmin,
    (req, res) => {
        const posts = loadPosts();

        const post =
            posts.find(
                item =>
                    item.id ===
                    req.params.id
            );

        if (!post) {
            return res.status(404).json({
                success: false,
                message:
                    "Post not found."
            });
        }

        if (
            post.file &&
            post.file.fileName
        ) {
            const filePath =
                path.join(
                    UPLOADS_DIR,
                    post.file.fileName
                );

            if (
                fs.existsSync(filePath)
            ) {
                try {
                    fs.unlinkSync(
                        filePath
                    );
                } catch {}
            }
        }

        const remaining =
            posts.filter(
                item =>
                    item.id !==
                    req.params.id
            );

        savePosts(remaining);

        res.json({
            success: true
        });
    }
);

// ========================================
// TEST
// ========================================

app.get(
    "/api/test",
    (req, res) => {
        res.json({
            success: true,
            message:
                "0MH Website is working!"
        });
    }
);

// ========================================
// SESSION DEBUG
// ========================================

app.get(
    "/api/session",
    (req, res) => {
        res.json({
            sessionExists:
                !!req.session,

            sessionID:
                req.sessionID || null,

            userId:
                req.session
                    ? req.session.userId || null
                    : null,

            loggedIn:
                !!getUser(req)
        });
    }
);

// ========================================
// MULTER ERRORS
// ========================================

app.use(
    (error, req, res, next) => {
        if (
            error instanceof
            multer.MulterError
        ) {
            if (
                error.code ===
                "LIMIT_FILE_SIZE"
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "File is too large. Maximum size is 100 MB."
                });
            }

            return res.status(400).json({
                success: false,
                message:
                    "File upload failed."
            });
        }

        console.error(
            "Server error:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Internal server error."
        });
    }
);

// ========================================
// START
// ========================================

app.listen(
    PORT,
    () => {
        console.log(
            `0MH Website is running at http://localhost:${PORT}`
        );

        console.log(
            "Owner account: 0relGT"
        );

        console.log(
            "Owner & Admin Powers: /staff"
        );
    }
);
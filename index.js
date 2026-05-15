import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";//remembers users activity across requests
import "dotenv/config";
import pkg from 'pg';
const { Pool } = pkg;

const app = express();
const port = process.env.PORT || 3000;
/* const db = new pg.Client({
    user : process.env.DB_USER,
    host : process.env.DB_HOST,
    database : process.env.DB_NAME,
    password : process.env.DB_PASSWORD,
    port : process.env.DB_PORT,
}); */
const pool = new Pool({
    connectionString: process.env.DB_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

//db.connect();

app.use(express.urlencoded({ extended: true }));

app.use(express.static("public"));

/** Admin gate: defaults in code; override via ADMIN_* in .env (empty ADMIN_USERNAME/EMAIL falls back). */
const ADMIN_ALLOWLIST = Object.freeze({
    username: process.env.ADMIN_USERNAME?.trim().toLowerCase(),
    email: process.env.ADMIN_EMAIL?.trim().toLowerCase(),
    password: process.env.ADMIN_PASSWORD,
});

function normalizeAdminUsername(value) {
    return String(value ?? "").trim().toLowerCase();
}

function normalizeAdminEmail(value) {
    return String(value ?? "").trim().toLowerCase();
}

async function ensureSchema() {
    // Keep changes minimal + backward compatible with existing columns.
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(255);`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'user';`);
    await pool.query(`UPDATE users SET role = 'user' WHERE role IS NULL;`);

    await pool.query(`ALTER TABLE posts ADD COLUMN IF NOT EXISTS author_id INTEGER REFERENCES users(id) ON DELETE SET NULL;`);
    await pool.query(`
        UPDATE posts p
        SET author_id = u.id
        FROM users u
        WHERE p.author_id IS NULL AND p.author_username = u.username;
    `);
}

function getAuth(req) {
    return req.session?.auth || null;
}

function setAuthSession(req, userRow) {
    req.session.auth = {
        id: userRow.id,
        username: userRow.username,
        role: userRow.role || "user",
    };
    // Backward compatibility with existing templates/routes.
    req.session.user = userRow.username;
}

function isAdminAuth(auth) {
    return auth?.role === "admin";
}

function isExactAdminCreds({ username, email, password }) {
    return (
        normalizeAdminUsername(username) === ADMIN_ALLOWLIST.username &&
        normalizeAdminEmail(email) === ADMIN_ALLOWLIST.email &&
        password === ADMIN_ALLOWLIST.password
    );
}

function requireAuth(req, res, next) {
    if (!getAuth(req)) return res.redirect("/login");
    return next();
}

function requireAdmin(req, res, next) {
    const auth = getAuth(req);
    if (!auth) return res.redirect("/login");
    if (!isAdminAuth(auth)) return res.status(403).send("Access Denied");
    return next();
}

async function getPostById(postId) {
    const result = await pool.query("SELECT * FROM posts WHERE id = $1", [postId]);
    return result.rows[0] || null;
}

function canModifyPost({ auth, post }) {
    if (!auth || !post) return false;
    if (isAdminAuth(auth)) return true;
    if (post.author_id && auth.id) return Number(post.author_id) === Number(auth.id);
    return post.author_username === auth.username;
}

app.set("trust proxy", 1);

app.use(
    session({
        secret: process.env.SESSION_SECRET || "fallback_secret",
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: "none",
            secure: process.env.NODE_ENV === "production",
            maxAge: 1000 * 60 * 60 * 12, // 12 hours
        },
    })
);

app.use((req, res, next) => {
    res.locals.auth = getAuth(req);
    res.locals.name = getAuth(req)?.username || null;
    res.locals.role = getAuth(req)?.role || null;
    next();
});

await ensureSchema();

app.get("/",(req,res) =>{
    res.render("index.ejs");
});

app.get("/about",(req,res)=>{
    res.render("about.ejs");
});

app.get("/read", async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM posts ORDER BY created_at DESC");
        res.render("read.ejs", { posts: result.rows });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error fetching public posts.");
    }
});

app.get("/signup",(req,res) =>{
    res.render("signup.ejs");
});

app.get("/login",(req,res)=>{
    res.render("login.ejs");
});

app.get("/submit",(req,res)=>{
    if(getAuth(req)) return res.render("submit.ejs");
    return res.redirect("/login");
});

app.post("/signup", async (req,res) =>{
    if(getAuth(req)){
        return res.send("You already have an account and are logged in.");
    } 
    const { name , email, password, role } = req.body;
    const requestedRole = role === "admin" ? "admin" : "user";
    try {
        if (!name || !password) return res.status(400).send("Missing required fields.");
        if (requestedRole === "admin") {
            if (!normalizeAdminEmail(email)) {
                return res.status(400).send("Email is required for admin signup.");
            }
            if (!isExactAdminCreds({ username: name, email, password })) {
                return res.status(403).send("Admin signup denied. Invalid admin credentials.");
            }
        }

        const signupName = String(name).trim();
        const checkResult = await pool.query("SELECT * FROM users WHERE LOWER(username) = LOWER($1)", [signupName]);
        if(checkResult.rows.length > 0){
            const existing = checkResult.rows[0];
            if (requestedRole === "admin" && existing.role !== "admin") {
                return res.status(403).send(
                    "This username is already registered without admin access. Log in as a user or pick a different username."
                );
            }
            return res.status(400).send("Username already exists. Please login.");
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const created = await pool.query(
            "INSERT INTO users (username, email, hashed_password, role) VALUES ($1, $2, $3, $4) RETURNING id, username, role",
            [signupName, email || null, hashedPassword, requestedRole]
        );

        setAuthSession(req, created.rows[0]);
        res.redirect("/dashboard");
    } catch(err) {
        console.error(err);
        res.status(500).send("Error creating user.");
    }
});

app.post("/login", async (req,res) =>{
    const { name, email, password, role } = req.body;
    const requestedRole = role === "admin" ? "admin" : "user";
    try {
        if (!name || !password) return res.status(400).send("Missing required fields.");
        if (requestedRole === "admin") {
            if (!normalizeAdminEmail(email)) {
                return res.status(400).send("Email is required for admin login.");
            }
            if (!isExactAdminCreds({ username: name, email, password })) {
                return res.status(403).send("Admin login denied. Invalid admin credentials.");
            }
        }

        const loginName = String(name).trim();
        const query = "SELECT * FROM users WHERE LOWER(username) = LOWER($1)";
        const result = await pool.query(query, [loginName]);
        if(result.rows.length === 0){
            if (requestedRole === "admin" && isExactAdminCreds({ username: name, email, password })) {
                const hashedPassword = await bcrypt.hash(password, 10);
                const created = await pool.query(
                    "INSERT INTO users (username, email, hashed_password, role) VALUES ($1, $2, $3, 'admin') RETURNING id, username, role",
                    [loginName, email || null, hashedPassword]
                );
                setAuthSession(req, created.rows[0]);
                return res.redirect("/admin/dashboard");
            }
            return res.status(400).send("Username does not exist. Please check if you have signed up.");
        }
        const user = result.rows[0];
        if (requestedRole === "admin" && user.role !== "admin") {
            return res.status(403).send("Admin login denied. Invalid admin credentials.");
        }
        if (requestedRole === "user" && user.role === "admin") {
            return res.status(403).send("Please login as Admin for this account.");
        }
        const dbPassword = user.hashed_password || user['hashed passwords'] || user.password;
        
        const isMatch = await bcrypt.compare(password, dbPassword);
        if(!isMatch){
            return res.status(400).send("Incorrect Password.");
        }
        
        setAuthSession(req, user);
        if (isAdminAuth(getAuth(req))) return res.redirect("/admin/dashboard");
        return res.redirect("/dashboard");
    } catch(err) {
        console.error(err);
        res.status(500).send("Login Failed.");
    }
});

app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.clearCookie("connect.sid");
        res.redirect("/login");
    });
});

app.get("/dashboard", requireAuth, (req, res) => {
    res.render("dashboard.ejs");
});

app.get("/profile", requireAuth, async (req, res) => {
    const auth = getAuth(req);
    try {
        const result = await pool.query("SELECT id, username, email, role FROM users WHERE id = $1", [auth.id]);
        const user = result.rows[0] || auth;
        res.render("profile.ejs", { user });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error loading profile.");
    }
});

app.get("/admin/dashboard", requireAdmin, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM posts ORDER BY created_at DESC");
        res.render("admin_dashboard.ejs", { posts: result.rows });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error loading admin dashboard.");
    }
});

app.post("/write", async (req,res) =>{
    const auth = getAuth(req);
    if(!auth) return res.redirect("/login");
    const { title, content } = req.body;
    try {
        const result = await pool.query(
            "INSERT INTO posts (title, content, author_username, author_id) VALUES ($1, $2, $3, $4) RETURNING id",
            [title, content, auth.username, auth.id]
        );
        res.redirect(`/post/${result.rows[0].id}`);
    } catch (err) {
        console.error(err);
        res.status(500).send("Error saving post.");
    }
});

app.get("/blogs", async (req, res) => {
    const auth = getAuth(req);
    if(!auth) return res.redirect("/login");
    try {
        const result = await pool.query("SELECT * FROM posts WHERE author_username = $1 ORDER BY created_at DESC", [auth.username]);
        res.render("blogs.ejs", { posts: result.rows });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error fetching posts.");
    }
});

app.post("/blogs", (req, res) => {
    res.redirect("/blogs");
});

app.get("/post/:id", async (req, res) => {
    const postId = req.params.id;
    try {
        const post = await getPostById(postId);
        if (!post) return res.status(404).send("Post not found.");
        const auth = getAuth(req);
        const isAuthor = !!auth && (post.author_username === auth.username || (post.author_id && Number(post.author_id) === Number(auth.id)));
        const isAdmin = isAdminAuth(auth);
        res.render("write.ejs", { 
            post: post, 
            isAuthor: isAuthor,
            isAdmin: isAdmin
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error fetching post.");
    }
});

app.get("/edit/:id", async (req, res) => {
    const auth = getAuth(req);
    if(!auth) return res.redirect("/login");
    const postId = req.params.id;
    try {
        const post = await getPostById(postId);
        if (!post) return res.status(404).send("Post not found.");
        if (!canModifyPost({ auth, post })) return res.status(403).send("Access Denied");
        res.render("edit.ejs", { post: post });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error fetching post for edit.");
    }
});

app.post("/update/:id", async (req, res) => {
    const auth = getAuth(req);
    if(!auth) return res.redirect("/login");
    const postId = req.params.id;
    const { title, content } = req.body;
    try {
        const post = await getPostById(postId);
        if (!post) return res.status(404).send("Post not found.");
        if (!canModifyPost({ auth, post })) return res.status(403).send("Access Denied");
        await pool.query("UPDATE posts SET title = $1, content = $2 WHERE id = $3", [title, content, postId]);
        res.redirect(`/post/${postId}`);
    } catch (err) {
        console.error(err);
        res.status(500).send("Error updating post.");
    }
});

app.post("/delete/:id", async (req, res) => {
    const auth = getAuth(req);
    if(!auth) return res.redirect("/login");
    const postId = req.params.id;
    try {
        const post = await getPostById(postId);
        if (!post) return res.status(404).send("Post not found.");
        if (!canModifyPost({ auth, post })) return res.status(403).send("Access Denied");
        await pool.query("DELETE FROM posts WHERE id = $1", [postId]);
        res.redirect("/read");
    } catch (err) {
        console.error(err);
        res.status(500).send("Error deleting post.");
    }
});

app.get("/feedback", (req, res) => {
    if(!getAuth(req)) return res.redirect("/login");
    res.render("feedback.ejs");
});

app.post("/feedback", async (req, res) => {
    if(!getAuth(req)) return res.redirect("/login");
    const feedback = req.body.feedback;
    const username = getAuth(req).username;
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS platform_feedback (
                id SERIAL PRIMARY KEY, 
                user_name VARCHAR(255) REFERENCES users(username) ON DELETE CASCADE, 
                content TEXT, 
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        try {
            await pool.query("ALTER TABLE platform_feedback RENAME COLUMN username TO user_name;");
        } catch (e) {
            // Error simply means it's already renamed or table is fresh
        }

        await pool.query("INSERT INTO platform_feedback (user_name, content) VALUES ($1, $2)", [username, feedback]);
        
        console.log(`\n\x1b[36m================ NEW FEEDBACK RECEIVED ================\x1b[0m`);
        console.log(`\x1b[35mFrom User:\x1b[0m ${username}`);
        console.log(`\x1b[33m${feedback}\x1b[0m`);
        console.log(`\x1b[36m========================================================\x1b[0m\n`);
        
        res.send("<script>alert('Thank you for your feedback! It has been successfully sent.'); window.location.href='/';</script>");
    } catch (err) {
        console.error("Error saving feedback:", err);
        res.status(500).send("Error saving feedback.");
    }
});

app.get("/index.ejs",(req,res)=>{
    res.render("index.ejs");
});

app.listen(port,()=>{
    console.log(`Listening on port ${port}`);
});
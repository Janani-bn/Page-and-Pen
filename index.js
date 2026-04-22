import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";//remembers users activity across requests
import "dotenv/config";

const app = express();
const port = process.env.PORT || 3000;
const db = new pg.Client({
    user : process.env.DB_USER,
    host : process.env.DB_HOST,
    database : process.env.DB_NAME,
    password : process.env.DB_PASSWORD,
    port : process.env.DB_PORT
});

db.connect();

app.use(express.urlencoded({ extended: true }));

app.use(express.static("public"));

app.use(
    session({
        secret: process.env.SESSION_SECRET || "fallback_secret",
        resave: false,
        saveUninitialized: false,
    })
);

app.get("/",(req,res) =>{
    res.render("index.ejs");
});

app.get("/about",(req,res)=>{
    res.render("about.ejs");
});

app.get("/read", async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM posts ORDER BY created_at DESC");
        res.render("read.ejs", { posts: result.rows, name: req.session.user });
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
    if(req.session.user) {
        res.render("submit.ejs", { name: req.session.user });
    } else {
        res.redirect("/login");
    }
});

app.post("/signup", async (req,res) =>{
    if(req.session.user){
        return res.send("You already have an account and are logged in.");
    } 
    const { name , password } = req.body;
    try {
        const checkResult = await db.query("SELECT * FROM users WHERE username = $1", [name]);
        if(checkResult.rows.length > 0){
            return res.status(400).send("Username already exists. Please login.");
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const queryUsers = "INSERT INTO users (username, hashed_password) VALUES ($1, $2)";
        await db.query(queryUsers, [name, hashedPassword]);
        
        req.session.user = name;
        res.redirect("/submit");
    } catch(err) {
        console.error(err);
        res.status(500).send("Error creating user.");
    }
});

app.post("/login", async (req,res) =>{
    const { name, password } = req.body;
    try {
        const query = "SELECT * FROM users WHERE username = $1";
        const result = await db.query(query, [name]);
        if(result.rows.length == 0){
            return res.status(400).send("Username does not exist. Please check if you have signed up.");
        }
        const user = result.rows[0];
        const dbPassword = user.hashed_password || user['hashed passwords'] || user.password;
        
        const isMatch = await bcrypt.compare(password, dbPassword);
        if(!isMatch){
            return res.status(400).send("Incorrect Password.");
        }
        
        req.session.user = name;
        res.redirect("/submit");
    } catch(err) {
        console.error(err);
        res.status(500).send("Login Failed.");
    }
});

app.post("/write", async (req,res) =>{
    if(!req.session.user) {
        return res.redirect("/login");
    }
    const { title, content } = req.body;
    try {
        const result = await db.query(
            "INSERT INTO posts (title, content, author_username) VALUES ($1, $2, $3) RETURNING id",
            [title, content, req.session.user]
        );
        res.redirect(`/post/${result.rows[0].id}`);
    } catch (err) {
        console.error(err);
        res.status(500).send("Error saving post.");
    }
});

app.get("/blogs", async (req, res) => {
    if(!req.session.user) {
        return res.redirect("/login");
    }
    try {
        const result = await db.query("SELECT * FROM posts WHERE author_username = $1 ORDER BY created_at DESC", [req.session.user]);
        res.render("blogs.ejs", { posts: result.rows, name: req.session.user });
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
        const result = await db.query("SELECT * FROM posts WHERE id = $1", [postId]);
        if (result.rows.length === 0) {
            return res.status(404).send("Post not found.");
        }
        const post = result.rows[0];
        const isAuthor = req.session.user === post.author_username;
        const isAdmin = req.session.user === process.env.ADMIN_USERNAME;
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
    if(!req.session.user) {
        return res.redirect("/login");
    }
    const postId = req.params.id;
    try {
        const result = await db.query("SELECT * FROM posts WHERE id = $1", [postId]);
        if (result.rows.length === 0) {
            return res.status(404).send("Post not found.");
        }
        const post = result.rows[0];
        if (post.author_username !== req.session.user) {
            return res.status(403).send("Unauthorized to edit this post.");
        }
        res.render("edit.ejs", { post: post, name: req.session.user });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error fetching post for edit.");
    }
});

app.post("/update/:id", async (req, res) => {
    if(!req.session.user) {
        return res.redirect("/login");
    }
    const postId = req.params.id;
    const { title, content } = req.body;
    try {
        await db.query(
            "UPDATE posts SET title = $1, content = $2 WHERE id = $3 AND author_username = $4",
            [title, content, postId, req.session.user]
        );
        res.redirect(`/post/${postId}`);
    } catch (err) {
        console.error(err);
        res.status(500).send("Error updating post.");
    }
});

app.post("/delete/:id", async (req, res) => {
    if(!req.session.user) {
        return res.redirect("/login");
    }
    const postId = req.params.id;
    const isAdmin = req.session.user === process.env.ADMIN_USERNAME;
    try {
        if (isAdmin) {
            await db.query("DELETE FROM posts WHERE id = $1", [postId]);
        } else {
            await db.query("DELETE FROM posts WHERE id = $1 AND author_username = $2", [postId, req.session.user]);
        }
        res.redirect("/read");
    } catch (err) {
        console.error(err);
        res.status(500).send("Error deleting post.");
    }
});

app.get("/feedback", (req, res) => {
    if(!req.session.user) {
        return res.redirect("/login");
    }
    res.render("feedback.ejs", { name: req.session.user });
});

app.post("/feedback", async (req, res) => {
    if(!req.session.user) {
        return res.redirect("/login");
    }
    const feedback = req.body.feedback;
    const username = req.session.user;
    try {
        await db.query(`
            CREATE TABLE IF NOT EXISTS platform_feedback (
                id SERIAL PRIMARY KEY, 
                user_name VARCHAR(255) REFERENCES users(username) ON DELETE CASCADE, 
                content TEXT, 
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        try {
            await db.query("ALTER TABLE platform_feedback RENAME COLUMN username TO user_name;");
        } catch (e) {
            // Error simply means it's already renamed or table is fresh
        }

        await db.query("INSERT INTO platform_feedback (user_name, content) VALUES ($1, $2)", [username, feedback]);
        
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
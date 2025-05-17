import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcryptjs from "bcryptjs";
import env from "dotenv";

env.config();

const app = express();
const port = 3000;
const saltRounds = 10;

// ✅ PostgreSQL connection using environment variables
const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

// Routes
app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      const hash = await bcryptjs.hash(password, saltRounds);
      await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [email, hash]);
      res.render("secrets.ejs");
    }
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).send("Internal server error.");
  }
});

app.post("/login", async (req, res) => {
  const email = req.body.username;
  const loginPassword = req.body.password;

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      const isMatch = await bcryptjs.compare(loginPassword, user.password);

      if (isMatch) {
        res.render("secrets.ejs");
      } else {
        res.send("Incorrect password.");
      }
    } else {
      res.send("User not found.");
    }
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).send("Internal server error.");
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

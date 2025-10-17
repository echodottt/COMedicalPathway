import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import sqlite3 from "sqlite3";
import { open } from "sqlite";

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

let db;

(async () => {
  db = await open({
    filename: "./users.db",
    driver: sqlite3.Database
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      email TEXT UNIQUE,
      password TEXT
    )
  `);
})();

// Signup endpoint
app.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    await db.run("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", [
      username,
      email,
      hashed
    ]);
    res.json({ message: "Signup successful!" });
  } catch (error) {
    if (error.message.includes("UNIQUE constraint failed")) {
      res.status(400).json({ error: "Email already registered." });
    } else {
      res.status(500).json({ error: error.message });
    }
  }
});

// Login endpoint
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await db.get("SELECT * FROM users WHERE email = ?", [email]);
    if (!user) return res.status(404).json({ error: "User not found." });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Incorrect password." });
    res.json({ message: "Login successful!", user: { id: user.id, username: user.username, email: user.email } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(port, () => console.log(`✅ Backend running on port ${port}`));

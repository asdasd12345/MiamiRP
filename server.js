require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

const isRender = process.env.RENDER === "true";
const dbPath = isRender ? '/tmp/miamirp.db' : path.resolve(__dirname, 'miamirp.db');

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('❌ Failed to connect to SQLite database:', err.message);
    process.exit(1);
  } else {
    console.log(`✅ Connected to SQLite DB at ${dbPath}`);
  }
});

// ✅ Create accounts table
db.run(`
  CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password_hash TEXT
  )
`);

// ✅ Create characters table
db.run(`
  CREATE TABLE IF NOT EXISTS characters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    name TEXT,
    age INTEGER,
    gender TEXT,
    posX REAL DEFAULT 0,
    posY REAL DEFAULT 0,
    posZ REAL DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES accounts(id)
  )
`);

// ✅ Register
app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: 'Email and password required' });

  try {
    const hash = await bcrypt.hash(password, 10);

    db.run(
      'INSERT INTO accounts (email, password_hash) VALUES (?, ?)',
      [email, hash],
      function (err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ message: 'Email already registered' });
          }
          console.error('❌ Register error:', err.message);
          return res.status(500).json({ message: 'Server error' });
        }

        res.status(200).json({ message: 'Registered successfully' });
      }
    );
  } catch (err) {
    console.error('❌ Bcrypt error:', err);
    res.status(500).json({ message: 'Encryption error' });
  }
});

// ✅ Login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: 'Missing credentials' });

  db.get('SELECT * FROM accounts WHERE email = ?', [email], async (err, user) => {
    if (err || !user) return res.status(401).json({ message: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET || 'supersecret'
    );

    res.json({ message: 'Login successful', token });
  });
});

// ✅ Verify token
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.status(200).json({ valid: true, user: req.user });
});

// ✅ Check if character exists
app.get('/api/character/exists', authenticateToken, (req, res) => {
  db.get('SELECT * FROM characters WHERE user_id = ?', [req.user.id], (err, row) => {
    if (err) return res.sendStatus(500);
    res.json({ exists: !!row });
  });
});

// ✅ Create character
app.post('/api/character/create', authenticateToken, (req, res) => {
  const { name, age, gender } = req.body;
  if (!name || !age || !gender)
    return res.status(400).json({ message: 'Missing character data' });

  db.run(
    'INSERT INTO characters (user_id, name, age, gender) VALUES (?, ?, ?, ?)',
    [req.user.id, name, age, gender],
    function (err) {
      if (err) return res.status(500).json({ message: 'Error creating character' });
      res.json({ message: 'Character created', characterId: this.lastID });
    }
  );
});

// ✅ Load character data
app.get('/api/character/load', authenticateToken, (req, res) => {
  db.get('SELECT * FROM characters WHERE user_id = ?', [req.user.id], (err, character) => {
    if (err || !character) return res.status(404).json({ message: 'Character not found' });
    res.json({ character });
  });
});

// ✅ Save character position
app.post('/api/character/savepos', authenticateToken, (req, res) => {
  const { posX, posY, posZ } = req.body;
  db.run(
    'UPDATE characters SET posX = ?, posY = ?, posZ = ? WHERE user_id = ?',
    [posX, posY, posZ, req.user.id],
    function (err) {
      if (err) return res.status(500).json({ message: 'Error saving position' });
      res.json({ message: 'Position saved' });
    }
  );
});

// ✅ JWT middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET || 'supersecret', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// ✅ Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 MiamiRP API running on port ${PORT}`);
});

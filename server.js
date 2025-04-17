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

// ✅ Use Render-safe path for the DB in production
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

// ✅ Create users table if it doesn’t exist
db.run(`
  CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password_hash TEXT
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
    if (err || !user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET || 'supersecret'
    );

    res.json({ message: 'Login successful', token });
  });
});

// ✅ Verify token for auto-login
app.get('/api/auth/verify', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401); // No token sent

  jwt.verify(token, process.env.JWT_SECRET || 'supersecret', (err, user) => {
    if (err) return res.sendStatus(403); // Invalid token
    res.status(200).json({ valid: true, user });
  });
});

// ✅ Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 MiamiRP API running on port ${PORT}`);
});

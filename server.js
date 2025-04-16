require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// DB connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  // Optional SSL for db4free or similar
  // ssl: {
  //   rejectUnauthorized: false
  // }
});

db.connect(err => {
  if (err) {
    console.error('❌ Database connection error:', err);
    process.exit(1); // Exit to trigger a redeploy or restart
  } else {
    console.log('✅ Connected to MiamiRP database');
  }
});

// REGISTER
app.post('/api/auth/register', async (req, res) => {
  console.log("📩 Incoming /register request:", req.body);
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

  try {
    const hash = await bcrypt.hash(password, 10);
    db.query(
      'INSERT INTO accounts (email, password_hash) VALUES (?, ?)',
      [email, hash],
      (err, result) => {
        if (err) {
          console.error("⚠️ MySQL insert error:", err);
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ message: 'Email already registered' });
          }
          return res.status(500).json({ message: 'Server error' });
        }
        console.log(`✅ Registered user: ${email}`);
        res.status(200).json({ message: 'Registered successfully' });
      }
    );
  } catch (err) {
    console.error("⚠️ Bcrypt error:", err);
    res.status(500).json({ message: 'Encryption error' });
  }
});

// LOGIN
app.post('/api/auth/login', (req, res) => {
  console.log("📩 Incoming /login request:", req.body);
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).json({ message: 'Missing credentials' });

  db.query('SELECT * FROM accounts WHERE email = ?', [email], async (err, results) => {
    if (err) {
      console.error("⚠️ MySQL select error:", err);
      return res.status(500).json({ message: 'Database error' });
    }

    if (results.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const user = results[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET);
    console.log(`✅ User logged in: ${email}`);
    res.json({ message: 'Login successful', token });
  });
});

// Set PORT fallback (important for Render)
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 MiamiRP API running on port ${PORT}`);
  console.log("✅ API is ready to receive requests.");
});

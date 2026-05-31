const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
app.use(express.json());

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'profiles',
  user: process.env.DB_USER || 'admin',
  password: process.env.DB_PASSWORD
});

// Initialize session table if it doesn't exist
async function initializeSessionTable() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS session (
        sid varchar NOT NULL COLLATE "default",
        sess json NOT NULL,
        expire timestamp(6) NOT NULL,
        PRIMARY KEY (sid)
      ) WITH (OIDS=FALSE);
      CREATE INDEX IF NOT EXISTS idx_session_expire ON session(expire);
    `);
    console.log('Session table initialized');
  } catch (err) {
    console.error('Error initializing session table:', err);
    throw err;
  }
}

// Session middleware
app.use(session({
  store: new pgSession({
    pool: pool,
    tableName: 'session'
  }),
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true,
    sameSite: 'strict'
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

// Middleware to check if user is logged in
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

// Sign up
app.post('/api/signup', async (req, res) => {
  const { username, email, firstName, lastName, password } = req.body;

  if (!username || !email || !firstName || !lastName || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const existing = await pool.query(
      'SELECT id FROM profiles WHERE email = $1 OR username = $2',
      [email, username]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'Email or username already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO profiles (first_name, last_name, email, username, password_hash)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, first_name, last_name, email, username, created_at`,
      [firstName, lastName, email, username, passwordHash]
    );

    res.status(201).json({ message: 'Account created', user: result.rows[0] });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const result = await pool.query(
      'SELECT id, first_name, last_name, email, username, phone, bio, password_hash, created_at FROM profiles WHERE username = $1',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Create session
    req.session.user = {
      id: user.id,
      first_name: user.first_name,
      last_name: user.last_name,
      email: user.email,
      username: user.username,
      phone: user.phone,
      bio: user.bio,
      created_at: user.created_at
    };

    const { password_hash, ...safeUser } = user;
    res.json({ message: 'Login successful', user: req.session.user });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get current user settings (protected)
app.get('/api/settings', requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, first_name, last_name, email, username, phone, bio, created_at, updated_at FROM profiles WHERE id = $1',
      [req.session.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error('Settings error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Change password (protected)
app.post('/api/change-password', requireLogin, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current password and new password are required' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters' });
  }

  try {
    // Get user's current password hash
    const result = await pool.query(
      'SELECT password_hash FROM profiles WHERE id = $1',
      [req.session.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Validate current password
    const valid = await bcrypt.compare(currentPassword, result.rows[0].password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Hash new password
    const newPasswordHash = await bcrypt.hash(newPassword, 10);

    // Update password
    await pool.query(
      'UPDATE profiles SET password_hash = $1, updated_at = NOW() WHERE id = $2',
      [newPasswordHash, req.session.user.id]
    );

    // Destroy session after password change
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destroy error:', err);
        return res.status(500).json({ error: 'Error during logout' });
      }
      res.json({ message: 'Password changed successfully. Please log in again.' });
    });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Logout
app.post('/api/logout', requireLogin, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ message: 'Logged out successfully' });
  });
});

// Check if user is logged in
app.get('/api/check-auth', (req, res) => {
  if (req.session.user) {
    res.json({ authenticated: true, user: req.session.user });
  } else {
    res.json({ authenticated: false });
  }
});

const PORT = process.env.PORT || 3000;

// Start server after initializing tables
(async () => {
  try {
    await initializeSessionTable();
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
})();
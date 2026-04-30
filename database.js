const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'authx.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'USER',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    locked INTEGER DEFAULT 0,
    login_attempts INTEGER DEFAULT 0
  )
`);

try { db.exec(`ALTER TABLE users ADD COLUMN locked_until DATETIME`); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0`); } catch (e) {}

db.exec(`
  CREATE TABLE IF NOT EXISTS reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    used INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    ip_address TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

module.exports = db;

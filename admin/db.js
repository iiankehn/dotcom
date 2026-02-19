/**
 * SQLite-backed account storage. Uses a single database file (default: data/accounts.db).
 * Set DB_PATH env var to override. Schema is created on first use.
 */
const path = require('path');
const fs = require('fs');

const defaultDir = path.join(__dirname, '..', 'data');
const defaultPath = path.join(defaultDir, 'accounts.db');

function getDbPath() {
  if (process.env.DB_PATH) {
    return path.resolve(process.env.DB_PATH);
  }
  if (!fs.existsSync(defaultDir)) {
    fs.mkdirSync(defaultDir, { recursive: true });
  }
  return defaultPath;
}

function openDb() {
  const Database = require('better-sqlite3');
  const dbPath = getDbPath();
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  return db;
}

let _db = null;

function getDb() {
  if (!_db) {
    _db = openDb();
    initSchema(_db);
  }
  return _db;
}

function initSchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS passkeys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      credential_id TEXT NOT NULL,
      credential_public_key TEXT NOT NULL,
      counter INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(user_id, credential_id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE INDEX IF NOT EXISTS idx_passkeys_user_id ON passkeys(user_id);
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
  `);
}

// --- User API (same shape as before for server compatibility) ---

function getAllUsers() {
  const db = getDb();
  const rows = db.prepare('SELECT id, username, password_hash FROM users').all();
  const passkeysByUser = db.prepare(
    'SELECT user_id, credential_id, credential_public_key, counter FROM passkeys'
  ).all();
  const map = {};
  passkeysByUser.forEach((p) => {
    if (!map[p.user_id]) map[p.user_id] = [];
    map[p.user_id].push({
      credentialID: p.credential_id,
      credentialPublicKey: p.credential_public_key, // base64url string
      counter: p.counter,
    });
  });
  return rows.map((r) => ({
    id: r.id,
    username: r.username,
    passwordHash: r.password_hash,
    passkeys: map[r.id] || [],
  }));
}

function findUserById(id) {
  const users = getAllUsers();
  return users.find((u) => u.id === id) || null;
}

function findUserByUsername(username) {
  const users = getAllUsers();
  return users.find((u) => u.username.toLowerCase() === username.toLowerCase()) || null;
}

function createUser(user) {
  const db = getDb();
  db.prepare(
    'INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)'
  ).run(user.id, user.username, user.passwordHash || null);
  return user;
}

function updateUserPassword(userId, passwordHash) {
  const db = getDb();
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(passwordHash, userId);
}

function addPasskey(userId, credentialID, credentialPublicKey, counter) {
  const db = getDb();
  const keyStr = typeof credentialPublicKey === 'string'
    ? credentialPublicKey
    : Buffer.from(credentialPublicKey).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  db.prepare(
    `INSERT INTO passkeys (user_id, credential_id, credential_public_key, counter)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(user_id, credential_id) DO UPDATE SET
       credential_public_key = excluded.credential_public_key,
       counter = excluded.counter`
  ).run(userId, credentialID, keyStr, counter ?? 0);
}

function updatePasskeyCounter(userId, credentialID, counter) {
  const db = getDb();
  db.prepare(
    'UPDATE passkeys SET counter = ? WHERE user_id = ? AND credential_id = ?'
  ).run(counter, userId, credentialID);
}

function deletePasskey(userId, credentialID) {
  const db = getDb();
  const result = db.prepare(
    'DELETE FROM passkeys WHERE user_id = ? AND credential_id = ?'
  ).run(userId, credentialID);
  return result.changes > 0;
}

function getPasskeys(userId) {
  const db = getDb();
  const rows = db.prepare(
    'SELECT credential_id, credential_public_key, counter FROM passkeys WHERE user_id = ?'
  ).all(userId);
  return rows.map((r) => ({
    credentialID: r.credential_id,
    credentialPublicKey: r.credential_public_key,
    counter: r.counter,
  }));
}

/** Reset all account data (for scripts / fresh deploy). */
function reset() {
  const db = getDb();
  db.exec('DELETE FROM passkeys; DELETE FROM users;');
}

module.exports = {
  getDb,
  getDbPath,
  getAllUsers,
  findUserById,
  findUserByUsername,
  createUser,
  updateUserPassword,
  addPasskey,
  updatePasskeyCounter,
  deletePasskey,
  getPasskeys,
  reset,
};

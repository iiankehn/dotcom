#!/usr/bin/env node
/**
 * Resets the admin account data (SQLite). All users and passkeys are removed.
 * Run from repo root: node admin/reset-users.js
 *
 * Database path: data/accounts.db (or set DB_PATH).
 * After reset, the first sign-up will create the first admin.
 */
const db = require('./db');

try {
  db.reset();
  console.log('Account data reset. Database:', db.getDbPath());
  console.log('No accounts exist. Restart the admin server if it is running.');
} catch (err) {
  console.error('Reset failed:', err.message);
  process.exit(1);
}

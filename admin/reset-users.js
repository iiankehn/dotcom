#!/usr/bin/env node
/**
 * Resets the users database by deleting admin/users.json.
 * Run from repo root: node admin/reset-users.js
 * After this, there are no accounts; the first sign-up will create the first admin.
 */
const path = require('path');
const fs = require('fs');

const USERS_FILE = path.join(__dirname, 'users.json');

if (fs.existsSync(USERS_FILE)) {
  fs.unlinkSync(USERS_FILE);
  console.log('Users database reset. admin/users.json removed. There are no accounts.');
} else {
  console.log('No users file found. Database is already empty.');
}

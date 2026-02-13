#!/usr/bin/env node
/**
 * Resets the admin auth state for a fresh deployment: removes users.json and
 * the encryption key. Run from repo root: node admin/reset-users.js
 *
 * After this, there are no accounts and the server will generate a new
 * encryption key on next start. The first sign-up will create the first admin.
 */
const path = require('path');
const fs = require('fs');

const USERS_FILE = path.join(__dirname, 'users.json');
const KEY_FILE = path.join(__dirname, '.encryption-key');

let removedUsers = false;
let removedKey = false;

if (fs.existsSync(USERS_FILE)) {
  fs.unlinkSync(USERS_FILE);
  console.log('Removed admin/users.json');
  removedUsers = true;
}

if (fs.existsSync(KEY_FILE)) {
  fs.unlinkSync(KEY_FILE);
  console.log('Removed admin/.encryption-key');
  removedKey = true;
}

if (!removedUsers && !removedKey) {
  console.log('No users.json or .encryption-key found. Already in a fresh state.');
} else {
  console.log('Reset complete. No accounts exist.');
  if (removedKey) {
    console.log('Restart the admin server; it will create a new encryption key.');
  } else {
    console.log('Restart the admin server to pick up the change.');
  }
}

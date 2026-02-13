const path = require('path');
const fs = require('fs');
const https = require('https');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const base64url = require('base64url');
const { v4: uuidv4 } = require('uuid');
const selfsigned = require('selfsigned');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production';

// Trust first proxy (e.g. nginx, Cloudflare) so req.secure and host are correct in production
if (isProduction || process.env.TRUST_PROXY === '1') {
  app.set('trust proxy', 1);
}

const ROOT_DIR = path.join(__dirname, '..');
const POSTS_FILE = path.join(ROOT_DIR, 'blog', 'posts.js');
const USERS_FILE = path.join(__dirname, 'users.json');
const KEY_FILE = path.join(__dirname, '.encryption-key');
const CERT_FILE = path.join(__dirname, '.ssl-cert.pem');
const KEY_CERT_FILE = path.join(__dirname, '.ssl-key.pem');
const ALGORITHM = 'aes-256-gcm';

function getEncryptionKey() {
  if (process.env.ENCRYPTION_KEY) {
    return process.env.ENCRYPTION_KEY;
  }
  if (fs.existsSync(KEY_FILE)) {
    return fs.readFileSync(KEY_FILE, 'utf8').trim();
  }
  const key = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(KEY_FILE, key, 'utf8');
  return key;
}

const ENCRYPTION_KEY = getEncryptionKey();

function getSSLOptions() {
  // Use provided certificates if available
  if (process.env.SSL_CERT && process.env.SSL_KEY) {
    return {
      cert: process.env.SSL_CERT,
      key: process.env.SSL_KEY,
    };
  }

  // Use certificate files if they exist
  if (fs.existsSync(CERT_FILE) && fs.existsSync(KEY_CERT_FILE)) {
    return {
      cert: fs.readFileSync(CERT_FILE, 'utf8'),
      key: fs.readFileSync(KEY_CERT_FILE, 'utf8'),
    };
  }

  // Generate self-signed certificate for local development
  // eslint-disable-next-line no-console
  console.log('Generating self-signed SSL certificate for local development...');
  const attrs = [{ name: 'commonName', value: 'localhost' }];
  const pems = selfsigned.generate(attrs, {
    keySize: 2048,
    days: 365,
    algorithm: 'sha256',
  });

  // Save certificates for reuse
  fs.writeFileSync(CERT_FILE, pems.cert, 'utf8');
  fs.writeFileSync(KEY_CERT_FILE, pems.private, 'utf8');

  // eslint-disable-next-line no-console
  console.log('Self-signed certificate generated. Browsers will show a security warning - this is normal for local development.');

  return {
    cert: pems.cert,
    key: pems.private,
  };
}

function getKeyBuffer() {
  // ENCRYPTION_KEY is a hex string; for AES-256 we need 32 bytes = 64 hex chars
  const hex = ENCRYPTION_KEY.length >= 64 ? ENCRYPTION_KEY.slice(0, 64) : ENCRYPTION_KEY.padEnd(64, '0');
  return Buffer.from(hex, 'hex');
}

function encrypt(text) {
  const iv = crypto.randomBytes(12); // recommended IV size for GCM
  const cipher = crypto.createCipheriv(ALGORITHM, getKeyBuffer(), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();
  return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedData) {
  const parts = encryptedData.split(':');
  if (parts.length !== 3) throw new Error('Invalid encrypted data format');
  const iv = Buffer.from(parts[0], 'hex');
  const authTag = Buffer.from(parts[1], 'hex');
  const encrypted = parts[2];
  const decipher = crypto.createDecipheriv(ALGORITHM, getKeyBuffer(), iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

app.use(express.json({ limit: '2mb' }));

// Optional CORS for cross-origin login (e.g. login page on CDN, API on api.example.com)
const corsOrigin = process.env.CORS_ORIGIN;
if (corsOrigin) {
  app.use((req, res, next) => {
    res.set('Access-Control-Allow-Origin', corsOrigin);
    res.set('Access-Control-Allow-Credentials', 'true');
    res.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
  });
}

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-session-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProduction,
  },
}));

// Serve main site so posts can be viewed while the admin is running.
// Skip static for /admin (served separately) and /auth (API routes only — static would return 405 for POST).
app.use((req, res, next) => {
  if (req.path.startsWith('/admin') || req.path.startsWith('/auth')) {
    return next();
  }
  return express.static(ROOT_DIR)(req, res, next);
});

function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) {
    return [];
  }
  try {
    const raw = fs.readFileSync(USERS_FILE, 'utf8');
    let decrypted;
    try {
      decrypted = decrypt(raw);
    } catch {
      // If decryption fails, try parsing as plain JSON (for migration)
      try {
        const data = JSON.parse(raw || '[]');
        if (Array.isArray(data) && data.length > 0) {
          // Migrate existing plain file to encrypted
          saveUsers(data);
          return data;
        }
      } catch {}
      return [];
    }
    const data = JSON.parse(decrypted || '[]');
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

function saveUsers(users) {
  const json = JSON.stringify(users, null, 2);
  const encrypted = encrypt(json);
  fs.writeFileSync(USERS_FILE, encrypted, 'utf8');
}

function findUserByUsername(username) {
  const users = loadUsers();
  return users.find((u) => u.username === username) || null;
}

function updateUser(user) {
  const users = loadUsers();
  const idx = users.findIndex((u) => u.id === user.id);
  if (idx === -1) return;
  users[idx] = user;
  saveUsers(users);
}

function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  // Allow login and auth endpoints
  if (req.path.startsWith('/admin/login') || req.path.startsWith('/auth/')) {
    return next();
  }
  // Protect admin UI and API routes
  if (req.path.startsWith('/admin') || req.path.startsWith('/api/')) {
    if (req.accepts('html')) {
      return res.redirect('/admin/login');
    }
    return res.status(401).json({ error: 'Not authenticated' });
  }
  return next();
}

function loadPosts() {
  // Clear require cache so we always get the latest version
  delete require.cache[require.resolve('../blog/posts.js')];
  // eslint-disable-next-line global-require
  const posts = require('../blog/posts.js');
  return Array.isArray(posts) ? posts : [];
}

function writeArchivePage(post) {
  if (!post || !post.slug) {
    return;
  }

  const relativePath = (post.archivePath && post.archivePath.trim())
    ? post.archivePath.trim()
    : `archive/${post.slug}.html`;

  post.archivePath = relativePath;
  post.hasArchive = true;

  const archiveFile = path.join(ROOT_DIR, 'blog', relativePath);
  const archiveDir = path.dirname(archiveFile);
  if (!fs.existsSync(archiveDir)) {
    fs.mkdirSync(archiveDir, { recursive: true });
  }

  const title = post.title || 'Blog post';
  const publishedLabel = post.publishedLabel || '';

  const html = `<!DOCTYPE html>
<html lang="en" class="antialiased bg-black text-zinc-100">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blog // Sevan Core</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Inter', 'sans-serif'],
                        mono: ['JetBrains Mono', 'monospace'],
                    },
                    colors: {
                        base: '#050505',
                        surface: '#121212',
                        muted: '#525252',
                        accent: '#262626'
                    }
                }
            }
        }
    </script>
</head>
<body class="bg-base min-h-screen text-zinc-200 selection:bg-white selection:text-black">

    <nav class="fixed top-0 left-0 w-full flex justify-between items-center px-6 py-6 z-50 mix-blend-difference bg-base/90 backdrop-blur-sm border-b border-white/5">
        <a href="../../index.html" class="font-mono text-xs tracking-widest uppercase hover:text-zinc-400 transition-colors">
            ← Return
        </a>
        <div class="font-mono text-xs text-muted">
            Sevan Core
        </div>
    </nav>

    <main class="pt-32 pb-24 px-6 max-w-5xl mx-auto">

        <header id="post-header" class="mb-20">
            <!-- Post content will be injected from posts.js -->
        </header>

        <footer class="border-t border-white/5 px-6 py-8 max-w-3xl mx-auto">
            <div class="flex flex-col md:flex-row justify-between items-start md:items-end mt-12 gap-6">
                <p class="font-mono text-xs text-zinc-400 max-w-sm leading-relaxed">
                    Copyright &copy; 2026 Sevan Core, LLC. All rights reserved.
                </p>
            </div>
        </footer>
    </main>

    <script src="../posts.js"></script>
    <script>
        (function () {
            const slug = ${JSON.stringify(post.slug)};
            if (!window.BLOG_POSTS) return;

            const post = window.BLOG_POSTS.find(function (p) {
                return p.slug === slug;
            });

            const container = document.getElementById('post-header');
            if (!post || !container) return;

            const h1 = document.createElement('h1');
            h1.className = 'text-4xl md:text-6xl font-light tracking-tight mb-4';
            h1.textContent = post.title || ${JSON.stringify(title)};

            const meta = document.createElement('p');
            meta.innerHTML = '<small>Published on ' +
                (post.publishedLabel || ${JSON.stringify(publishedLabel)}) +
                ' by <a href="../../about.html">Iian Kehn</a></small>';

            const bodyWrapper = document.createElement('div');
            if (post.articleHtml) {
                bodyWrapper.innerHTML = post.articleHtml;
            }

            container.appendChild(h1);
            container.appendChild(meta);
            container.appendChild(document.createElement('br'));
            container.appendChild(bodyWrapper);
        })();
    </script>
</body>
</html>
`;

  fs.writeFileSync(archiveFile, html, 'utf8');
}

function savePosts(posts) {
  const normalizedPosts = posts.map((post) => {
    if (!post || !post.slug) return post;
    const p = { ...post };
    if (!p.archivePath) {
      p.archivePath = `archive/${p.slug}.html`;
    }
    p.hasArchive = true;
    return p;
  });

  const header = [
    '// Generated blog posts data file.',
    '// This file is managed by the admin panel. Manual edits may be overwritten.',
    '',
    'const BLOG_POSTS = '
  ].join('\n');

  const postsJson = JSON.stringify(normalizedPosts, null, 2);

  const footer = [
    ';',
    '',
    'if (typeof window !== \'undefined\') {',
    '  window.BLOG_POSTS = BLOG_POSTS;',
    '}',
    '',
    'if (typeof module !== \'undefined\') {',
    '  module.exports = BLOG_POSTS;',
    '}',
    ''
  ].join('\n');

  const contents = `${header}${postsJson}${footer}`;
  fs.writeFileSync(POSTS_FILE, contents, 'utf8');

  // Ensure archive pages exist for all posts
  normalizedPosts.forEach((post) => {
    writeArchivePage(post);
  });
}

// --- Auth routes ---

app.get('/auth/info', (req, res) => {
  const users = loadUsers();
  res.json({
    hasUser: users.length > 0,
    authenticated: !!req.session.userId,
  });
});

app.get('/auth/me', (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const users = loadUsers();
  const user = users.find((u) => u.id === req.session.userId);
  if (!user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  return res.json({
    username: user.username,
    passkeyCount: (user.passkeys || []).length,
    passkeys: (user.passkeys || []).map((p, i) => ({
      id: p.credentialID,
      label: `Passkey ${i + 1}`,
    })),
  });
});

const MIN_PASSWORD_LENGTH = 8;

app.post('/auth/register', async (req, res) => {
  const { username, password } = req.body || {};
  const rawUsername = (username && typeof username === 'string') ? username.trim() : '';
  if (!rawUsername || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    return res.status(400).json({ error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters` });
  }

  const users = loadUsers();
  if (users.some((u) => u.username.toLowerCase() === rawUsername.toLowerCase())) {
    return res.status(409).json({ error: 'Username already taken' });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const user = {
    id: uuidv4(),
    username: rawUsername,
    passwordHash,
    passkeys: [],
  };
  users.push(user);
  saveUsers(users);
  req.session.userId = user.id;
  return res.status(201).json({ username: user.username });
});

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }
  const users = loadUsers();
  const user = users.find((u) => u.username === username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const ok = await bcrypt.compare(password, user.passwordHash || '');
  if (!ok) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  req.session.userId = user.id;
  return res.json({ username: user.username });
});

app.post('/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.status(204).send();
  });
});

app.post('/auth/change-password', async (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current password and new password are required' });
  }
  if (newPassword.length < MIN_PASSWORD_LENGTH) {
    return res.status(400).json({ error: `New password must be at least ${MIN_PASSWORD_LENGTH} characters` });
  }
  const users = loadUsers();
  const user = users.find((u) => u.id === req.session.userId);
  if (!user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const ok = await bcrypt.compare(currentPassword, user.passwordHash || '');
  if (!ok) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  user.passwordHash = await bcrypt.hash(newPassword, 12);
  updateUser(user);
  return res.json({ ok: true });
});

app.delete('/auth/webauthn/credentials/:id', (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const rawId = req.params.id ? decodeURIComponent(req.params.id) : '';
  const credentialId = rawId.replace(/-/g, '+').replace(/_/g, '/');
  if (!credentialId) {
    return res.status(400).json({ error: 'Credential ID required' });
  }
  const users = loadUsers();
  const user = users.find((u) => u.id === req.session.userId);
  if (!user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  user.passkeys = user.passkeys || [];
  const before = user.passkeys.length;
  user.passkeys = user.passkeys.filter((cred) => {
    if (cred.credentialID === credentialId || cred.credentialID === rawId) return false;
    try {
      const buf = base64url.toBuffer(cred.credentialID);
      const decoded = base64url.encode(buf);
      return decoded !== credentialId && decoded !== rawId;
    } catch {
      return true;
    }
  });
  if (user.passkeys.length === before) {
    return res.status(404).json({ error: 'Credential not found' });
  }
  updateUser(user);
  return res.status(204).send();
});

// Passkey (WebAuthn) configuration — in production set RP_ID and RP_ORIGIN to your public URL (e.g. https://admin.example.com)
const rpName = 'Sevan Core Admin';
const rpID = process.env.RP_ID || 'localhost';
const expectedOrigin = process.env.RP_ORIGIN || 'https://localhost:3000';

app.post('/auth/webauthn/register/options', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const users = loadUsers();
  const user = users.find((u) => u.id === req.session.userId);
  if (!user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const options = generateRegistrationOptions({
    rpName,
    rpID,
    userID: user.id,
    userName: user.username,
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
    excludeCredentials: (user.passkeys || []).map((cred) => ({
      id: base64url.toBuffer(cred.credentialID),
      type: 'public-key',
    })),
  });

  req.session.currentChallenge = options.challenge;
  res.json(options);
});

app.post('/auth/webauthn/register/verify', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const users = loadUsers();
  const user = users.find((u) => u.id === req.session.userId);
  if (!user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  const expectedChallenge = req.session.currentChallenge;
  try {
    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
    });

    const { verified, registrationInfo } = verification;
    if (!verified || !registrationInfo) {
      return res.status(400).json({ error: 'Registration verification failed' });
    }

    const {
      credentialPublicKey,
      credentialID,
      counter,
    } = registrationInfo;

    const newPasskey = {
      credentialID: base64url(credentialID),
      credentialPublicKey: base64url(credentialPublicKey),
      counter,
    };

    user.passkeys = user.passkeys || [];
    const existingIdx = user.passkeys.findIndex(
      (cred) => cred.credentialID === newPasskey.credentialID,
    );
    if (existingIdx >= 0) {
      user.passkeys[existingIdx] = newPasskey;
    } else {
      user.passkeys.push(newPasskey);
    }

    updateUser(user);
    req.session.currentChallenge = undefined;
    return res.json({ verified: true });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    return res.status(400).json({ error: 'Registration verification failed' });
  }
});

app.post('/auth/webauthn/login/options', (req, res) => {
  const { username } = req.body || {};
  if (!username) {
    return res.status(400).json({ error: 'username is required' });
  }
  const users = loadUsers();
  const user = users.find((u) => u.username === username);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const options = generateAuthenticationOptions({
    rpID,
    userVerification: 'preferred',
    allowCredentials: (user.passkeys || []).map((cred) => ({
      id: base64url.toBuffer(cred.credentialID),
      type: 'public-key',
    })),
  });

  req.session.currentChallenge = options.challenge;
  req.session.loginUserId = user.id;
  res.json(options);
});

app.post('/auth/webauthn/login/verify', async (req, res) => {
  const users = loadUsers();
  const user = users.find((u) => u.id === req.session.loginUserId);
  if (!user) {
    return res.status(400).json({ error: 'No pending WebAuthn login' });
  }

  const expectedChallenge = req.session.currentChallenge;

  const body = req.body;
  const credID = body.rawId && base64url.toBuffer(body.rawId);
  const credRecord = (user.passkeys || []).find(
    (cred) => base64url.toBuffer(cred.credentialID).equals(credID),
  );
  if (!credRecord) {
    return res.status(400).json({ error: 'Unknown credential' });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: base64url.toBuffer(credRecord.credentialID),
        credentialPublicKey: base64url.toBuffer(credRecord.credentialPublicKey),
        counter: credRecord.counter,
      },
    });

    const { verified, authenticationInfo } = verification;
    if (!verified || !authenticationInfo) {
      return res.status(400).json({ error: 'Authentication failed' });
    }

    credRecord.counter = authenticationInfo.newCounter;
    updateUser(user);

    req.session.userId = user.id;
    req.session.currentChallenge = undefined;
    req.session.loginUserId = undefined;

    return res.json({ verified: true, username: user.username });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    return res.status(400).json({ error: 'Authentication failed' });
  }
});

// Admin UI routes
app.get('/admin/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.use('/admin', requireAuth, express.static(__dirname));

// Protect all API routes
app.use('/api', requireAuth);

// API: get all posts
app.get('/api/posts', (req, res) => {
  try {
    const posts = loadPosts();
    res.json(posts);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load posts:', err);
    res.status(500).json({ error: 'Failed to load posts' });
  }
});

// API: get a single post
app.get('/api/posts/:slug', (req, res) => {
  try {
    const posts = loadPosts();
    const post = posts.find((p) => p.slug === req.params.slug);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }
    return res.json(post);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to load post:', err);
    return res.status(500).json({ error: 'Failed to load post' });
  }
});

// API: create a post
app.post('/api/posts', (req, res) => {
  try {
    const posts = loadPosts();
    const newPost = req.body || {};

    if (!newPost.slug || !newPost.title) {
      return res.status(400).json({ error: 'slug and title are required' });
    }

    if (posts.some((p) => p.slug === newPost.slug)) {
      return res.status(409).json({ error: 'Post with this slug already exists' });
    }

    posts.push(newPost);
    savePosts(posts);
    return res.status(201).json(newPost);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to create post:', err);
    return res.status(500).json({ error: 'Failed to create post' });
  }
});

// API: update a post
app.put('/api/posts/:slug', (req, res) => {
  try {
    const posts = loadPosts();
    const index = posts.findIndex((p) => p.slug === req.params.slug);

    if (index === -1) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const updated = { ...posts[index], ...req.body };
    posts[index] = updated;
    savePosts(posts);
    return res.json(updated);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to update post:', err);
    return res.status(500).json({ error: 'Failed to update post' });
  }
});

// API: delete a post
app.delete('/api/posts/:slug', (req, res) => {
  try {
    const posts = loadPosts();
    const index = posts.findIndex((p) => p.slug === req.params.slug);

    if (index === -1) {
      return res.status(404).json({ error: 'Post not found' });
    }

    posts.splice(index, 1);
    savePosts(posts);
    return res.status(204).send();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Failed to delete post:', err);
    return res.status(500).json({ error: 'Failed to delete post' });
  }
});

const sslOptions = getSSLOptions();
const server = https.createServer(sslOptions, app);

server.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`Admin server running at https://localhost:${PORT}`);
  // eslint-disable-next-line no-console
  console.log('Note: If using a self-signed certificate, your browser will show a security warning.');
  // eslint-disable-next-line no-console
  console.log('This is normal for local development. Click "Advanced" and proceed to continue.');
});


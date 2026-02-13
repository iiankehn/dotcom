function getApiBase() {
  const meta = document.querySelector('meta[name="api-base"]');
  const base = meta ? (meta.getAttribute('content') || '').trim() : '';
  return base.replace(/\/+$/, '');
}

async function fetchJson(url, options) {
  const base = getApiBase();
  const fullUrl = base ? base + url : url;
  const opts = { ...options, credentials: 'include' };
  const res = await fetch(fullUrl, opts);
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(text || `Request failed with ${res.status}`);
  }
  return res.json().catch(() => null);
}

const form = document.getElementById('auth-form');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const passwordConfirmWrap = document.getElementById('password-confirm-wrap');
const passwordConfirmInput = document.getElementById('password-confirm');
const primaryBtn = document.getElementById('primary-btn');
const modeBanner = document.getElementById('mode-banner');
const statusEl = document.getElementById('status');
const passkeyLoginBtn = document.getElementById('passkey-login-btn');
const createPasskeyBtn = document.getElementById('create-passkey-btn');
const toggleModeBtn = document.getElementById('toggle-mode-btn');
const subtitleText = document.getElementById('subtitle-text');

let hasUser = false;
let isSignUpMode = false;

function setStatus(msg, isError) {
  statusEl.textContent = msg || '';
  statusEl.className = 'text-[11px] font-mono ' + (isError ? 'text-red-300' : 'text-zinc-400');
}

function setSignUpMode(signUp) {
  isSignUpMode = signUp;
  if (passwordConfirmWrap) {
    passwordConfirmWrap.classList.toggle('hidden', !signUp);
  }
  if (passwordConfirmInput) {
    passwordConfirmInput.required = signUp;
    passwordConfirmInput.value = '';
  }
  if (primaryBtn) {
    primaryBtn.textContent = signUp ? 'Create account' : 'Sign in';
  }
  if (subtitleText) {
    subtitleText.textContent = signUp ? 'Create an account to manage blog posts.' : 'Sign in to manage blog posts.';
  }
  passkeyLoginBtn.style.display = signUp ? 'none' : '';
  setStatus('');
}

function updateToggleModeButton() {
  if (!toggleModeBtn) return;
  toggleModeBtn.textContent = isSignUpMode ? 'Already have an account? Sign in' : 'Create an account';
}

const logoutMessageEl = document.getElementById('logout-message');

async function init() {
  const params = new URLSearchParams(window.location.search);
  if (params.get('logged_out') === '1') {
    if (logoutMessageEl) {
      logoutMessageEl.textContent = 'You have successfully logged out. If you wish to access the portal again you must re-login.';
      logoutMessageEl.classList.remove('hidden');
    }
    if (window.history && window.history.replaceState) {
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }

  try {
    const info = await fetchJson('/auth/info');
    hasUser = !!info?.hasUser;
    if (!hasUser) {
      modeBanner.textContent = 'Create the first admin account.';
      primaryBtn.textContent = 'Create account';
      setSignUpMode(true);
      if (toggleModeBtn) toggleModeBtn.closest('p').classList.add('hidden');
    } else {
      modeBanner.textContent = 'Enter your credentials to sign in.';
      primaryBtn.textContent = 'Sign in';
      setSignUpMode(false);
      if (toggleModeBtn) toggleModeBtn.closest('p').classList.remove('hidden');
    }
    updateToggleModeButton();

    if (!('PublicKeyCredential' in window)) {
      passkeyLoginBtn.disabled = true;
      passkeyLoginBtn.textContent = 'Passkeys not supported';
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    setStatus('Failed to load auth status', true);
  }
}

toggleModeBtn.addEventListener('click', () => {
  isSignUpMode = !isSignUpMode;
  setSignUpMode(isSignUpMode);
  updateToggleModeButton();
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const username = usernameInput.value.trim();
  const password = passwordInput.value;

  if (!username || !password) {
    setStatus('Username and password are required', true);
    return;
  }

  if (isSignUpMode) {
    const confirmPassword = passwordConfirmInput ? passwordConfirmInput.value : '';
    if (password !== confirmPassword) {
      setStatus('Passwords do not match', true);
      return;
    }
    if (password.length < 8) {
      setStatus('Password must be at least 8 characters', true);
      return;
    }
  }

  try {
    setStatus(isSignUpMode ? 'Creating account…' : 'Signing in…');
    const payload = { username, password };
    if (isSignUpMode) {
      await fetchJson('/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
    } else {
      await fetchJson('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
    }

    setStatus('Signed in', false);
    createPasskeyBtn.classList.remove('hidden');
    window.location.href = getApiBase() ? getApiBase() + '/admin/' : '/admin/';
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    const message = (err && err.message) ? err.message : 'Authentication failed';
    setStatus(message, true);
  }
});

async function createPasskey() {
  try {
    setStatus('Preparing passkey registration…');
    const options = await fetchJson('/auth/webauthn/register/options', {
      method: 'POST',
    });

    options.challenge = Uint8Array.from(
      atob(options.challenge.replace(/-/g, '+').replace(/_/g, '/')),
      (c) => c.charCodeAt(0),
    );
    options.user.id = Uint8Array.from(
      atob(options.user.id.replace(/-/g, '+').replace(/_/g, '/')),
      (c) => c.charCodeAt(0),
    );
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map((cred) => ({
        ...cred,
        id: Uint8Array.from(
          atob(cred.id.replace(/-/g, '+').replace(/_/g, '/')),
          (c) => c.charCodeAt(0),
        ),
      }));
    }

    const credential = await navigator.credentials.create({ publicKey: options });
    const attestationResponse = {
      id: credential.id,
      rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
      type: credential.type,
      clientExtensionResults: credential.getClientExtensionResults(),
      response: {
        attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
        clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
      },
    };

    await fetchJson('/auth/webauthn/register/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(attestationResponse),
    });

    setStatus('Passkey added to your account', false);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    setStatus('Failed to add passkey', true);
  }
}

async function loginWithPasskey() {
  const username = usernameInput.value.trim();
  if (!username) {
    setStatus('Enter your username before using a passkey', true);
    return;
  }

  try {
    setStatus('Preparing passkey login…');
    const options = await fetchJson('/auth/webauthn/login/options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username }),
    });

    options.challenge = Uint8Array.from(
      atob(options.challenge.replace(/-/g, '+').replace(/_/g, '/')),
      (c) => c.charCodeAt(0),
    );
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map((cred) => ({
        ...cred,
        id: Uint8Array.from(
          atob(cred.id.replace(/-/g, '+').replace(/_/g, '/')),
          (c) => c.charCodeAt(0),
        ),
      }));
    }

    const assertion = await navigator.credentials.get({ publicKey: options });
    const authResponse = {
      id: assertion.id,
      rawId: btoa(String.fromCharCode(...new Uint8Array(assertion.rawId))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
      type: assertion.type,
      clientExtensionResults: assertion.getClientExtensionResults(),
      response: {
        authenticatorData: btoa(String.fromCharCode(...new Uint8Array(assertion.response.authenticatorData))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
        clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(assertion.response.clientDataJSON))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
        signature: btoa(String.fromCharCode(...new Uint8Array(assertion.response.signature))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
        userHandle: assertion.response.userHandle
          ? btoa(String.fromCharCode(...new Uint8Array(assertion.response.userHandle))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
          : null,
      },
    };

    await fetchJson('/auth/webauthn/login/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(authResponse),
    });

    setStatus('Signed in with passkey', false);
    window.location.href = getApiBase() ? getApiBase() + '/admin/' : '/admin/';
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    setStatus('Failed to sign in with passkey', true);
  }
}

createPasskeyBtn.addEventListener('click', () => {
  if (!('PublicKeyCredential' in window)) {
    setStatus('Passkeys not supported in this browser', true);
    return;
  }
  createPasskey();
});

passkeyLoginBtn.addEventListener('click', () => {
  if (!('PublicKeyCredential' in window)) {
    setStatus('Passkeys not supported in this browser', true);
    return;
  }
  loginWithPasskey();
});

init();


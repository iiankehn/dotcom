(function () {
  function getApiBase() {
    const meta = document.querySelector('meta[name="api-base"]');
    const base = meta ? (meta.getAttribute('content') || '').trim() : '';
    return base.replace(/\/+$/, '');
  }

  async function fetchJson(url, options) {
    const base = getApiBase();
    const fullUrl = base ? base + url : url;
    const res = await fetch(fullUrl, { ...options, credentials: 'include' });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(text || 'Request failed');
    }
    return res.json().catch(() => null);
  }

  const form = document.getElementById('auth-form');
  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');
  const passkeyBtn = document.getElementById('passkey-btn');
  const passwordToggle = document.getElementById('password-toggle');
  const passwordSection = document.getElementById('password-section');
  const passwordSubmit = document.getElementById('password-submit');
  const statusEl = document.getElementById('status');
  const logoutMessageEl = document.getElementById('logout-message');

  function setStatus(msg, isError) {
    statusEl.textContent = msg || '';
    statusEl.className = 'text-[11px] font-mono min-h-[1.25rem] ' + (isError ? 'text-red-300' : 'text-zinc-400');
  }

  // Logout message
  const params = new URLSearchParams(window.location.search);
  if (params.get('logged_out') === '1') {
    if (logoutMessageEl) {
      logoutMessageEl.textContent = 'You’ve been signed out.';
      logoutMessageEl.classList.remove('hidden');
    }
    if (window.history && window.history.replaceState) {
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }

  if (!('PublicKeyCredential' in window)) {
    passkeyBtn.disabled = true;
    passkeyBtn.textContent = 'Passkeys not supported';
  }

  passwordToggle.addEventListener('click', () => {
    passwordSection.classList.toggle('hidden');
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    if (!username || !password) {
      setStatus('Username and password are required', true);
      return;
    }
    try {
      setStatus('Signing in…');
      const data = await fetchJson('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      setStatus('', false);
      if (data.pendingPasskeyPrompt) {
        window.location.href = (getApiBase() || '') + '/admin/add-passkey.html';
      } else {
        window.location.href = (getApiBase() || '') + '/admin/';
      }
    } catch (err) {
      setStatus(err.message || 'Sign in failed', true);
    }
  });

  passkeyBtn.addEventListener('click', async () => {
    const username = usernameInput.value.trim();
    if (!username) {
      setStatus('Enter your username first', true);
      return;
    }
    try {
      setStatus('Preparing passkey…');
      const options = await fetchJson('/auth/webauthn/login/options', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      });

      options.challenge = Uint8Array.from(
        atob(options.challenge.replace(/-/g, '+').replace(/_/g, '/')),
        (c) => c.charCodeAt(0)
      );
      if (options.allowCredentials) {
        options.allowCredentials = options.allowCredentials.map((cred) => ({
          ...cred,
          id: Uint8Array.from(
            atob(cred.id.replace(/-/g, '+').replace(/_/g, '/')),
            (c) => c.charCodeAt(0)
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

      setStatus('', false);
      window.location.href = (getApiBase() || '') + '/admin/';
    } catch (err) {
      setStatus(err.message || 'Passkey sign-in failed', true);
    }
  });
})();

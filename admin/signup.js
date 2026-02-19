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

  const form = document.getElementById('signup-form');
  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');
  const passwordConfirmInput = document.getElementById('password-confirm');
  const statusEl = document.getElementById('status');

  function setStatus(msg, isError) {
    statusEl.textContent = msg || '';
    statusEl.className = 'text-[11px] font-mono min-h-[1.25rem] ' + (isError ? 'text-red-300' : 'text-zinc-400');
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    const confirm = passwordConfirmInput.value;

    if (!username || !password) {
      setStatus('Username and password are required', true);
      return;
    }
    if (password.length < 8) {
      setStatus('Password must be at least 8 characters', true);
      return;
    }
    if (password !== confirm) {
      setStatus('Passwords do not match', true);
      return;
    }

    try {
      setStatus('Creating account…');
      await fetchJson('/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      setStatus('', false);
      window.location.href = (getApiBase() || '') + '/admin/add-passkey.html';
    } catch (err) {
      setStatus(err.message || 'Sign up failed', true);
    }
  });
})();

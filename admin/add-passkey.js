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

  const addBtn = document.getElementById('add-passkey-btn');
  const skipLink = document.getElementById('skip-link');
  const statusEl = document.getElementById('status');

  function setStatus(msg, isError) {
    statusEl.textContent = msg || '';
    statusEl.className = 'text-[11px] font-mono min-h-[1.25rem] ' + (isError ? 'text-red-300' : 'text-zinc-400');
  }

  if (!('PublicKeyCredential' in window)) {
    addBtn.disabled = true;
    addBtn.textContent = 'Passkeys not supported';
  }

  function toUint8Array(value) {
    if (typeof value === 'string') {
      if (/^[A-Za-z0-9_-]+=*$/.test(value) && value.length % 4 !== 1) {
        try {
          return Uint8Array.from(
            atob(value.replace(/-/g, '+').replace(/_/g, '/')),
            (c) => c.charCodeAt(0)
          );
        } catch (_) {}
      }
      return new TextEncoder().encode(value);
    }
    if (value && value.data && Array.isArray(value.data)) {
      return new Uint8Array(value.data);
    }
    return new Uint8Array(0);
  }

  addBtn.addEventListener('click', async () => {
    try {
      setStatus('Preparing…');
      const options = await fetchJson('/auth/webauthn/register/options', { method: 'POST' });

      if (!options || options.challenge === undefined) {
        setStatus('Invalid response from server. Try signing in again.', true);
        return;
      }

      options.challenge = toUint8Array(options.challenge);
      options.user.id = toUint8Array(options.user?.id);
      if (options.excludeCredentials && options.excludeCredentials.length) {
        options.excludeCredentials = options.excludeCredentials.map((cred) => ({
          ...cred,
          id: toUint8Array(cred.id),
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

      setStatus('Passkey added. Redirecting…', false);
      setTimeout(() => {
        window.location.href = (getApiBase() || '') + '/admin/';
      }, 800);
    } catch (err) {
      setStatus(err.message || 'Failed to add passkey', true);
    }
  });

  skipLink.addEventListener('click', async (e) => {
    e.preventDefault();
    try {
      await fetchJson('/auth/dismiss-passkey-prompt', { method: 'POST' });
    } catch (_) {}
    window.location.href = (getApiBase() || '') + '/admin/';
  });
})();

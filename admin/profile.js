(function () {
  const usernameEl = document.getElementById('profile-username');
  const changePasswordSection = document.getElementById('change-password-section');
  const setPasswordSection = document.getElementById('set-password-section');
  const changePasswordForm = document.getElementById('change-password-form');
  const setPasswordForm = document.getElementById('set-password-form');
  const currentPasswordInput = document.getElementById('current-password');
  const newPasswordInput = document.getElementById('new-password');
  const newPasswordConfirmInput = document.getElementById('new-password-confirm');
  const setNewPasswordInput = document.getElementById('set-new-password');
  const setNewPasswordConfirmInput = document.getElementById('set-new-password-confirm');
  const passwordStatusEl = document.getElementById('password-status');
  const setPasswordStatusEl = document.getElementById('set-password-status');
  const passkeysListEl = document.getElementById('passkeys-list');
  const passkeysStatusEl = document.getElementById('passkeys-status');
  const accountLogoutLink = document.getElementById('account-logout');

  function setPasswordStatus(msg, isError) {
    passwordStatusEl.textContent = msg || '';
    passwordStatusEl.className = 'text-[11px] font-mono min-h-[1.25rem] ' + (isError ? 'text-red-300' : 'text-zinc-400');
  }

  function setSetPasswordStatus(msg, isError) {
    setPasswordStatusEl.textContent = msg || '';
    setPasswordStatusEl.className = 'text-[11px] font-mono min-h-[1.25rem] ' + (isError ? 'text-red-300' : 'text-zinc-400');
  }

  async function fetchJson(url, options) {
    const res = await fetch(url, { ...options, credentials: 'include' });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(text || 'Request failed');
    }
    return res.json().catch(() => null);
  }

  async function loadProfile() {
    try {
      const me = await fetchJson('/auth/me');
      if (usernameEl) usernameEl.textContent = me.username || '—';

      if (changePasswordSection && setPasswordSection) {
        if (me.hasPassword) {
          changePasswordSection.classList.remove('hidden');
          setPasswordSection.classList.add('hidden');
        } else {
          changePasswordSection.classList.add('hidden');
          setPasswordSection.classList.remove('hidden');
        }
      }

      if (passkeysListEl) {
        passkeysListEl.innerHTML = '';
        const passkeys = me.passkeys || [];
        if (passkeys.length === 0) {
          passkeysListEl.innerHTML = '<li class="text-xs text-zinc-500">No passkeys registered.</li>';
        } else {
          passkeys.forEach((pk) => {
            const li = document.createElement('li');
            li.className = 'flex items-center justify-between gap-3 py-2 border-b border-white/5';
            li.innerHTML = '<span class="text-sm font-mono text-zinc-300">' + (pk.label || 'Passkey') + '</span>' +
              '<button type="button" class="remove-passkey px-2 py-1 rounded border border-red-500/50 text-[11px] font-mono text-red-200 hover:bg-red-500/10" data-id="' + (pk.id || '').replace(/"/g, '&quot;') + '">Remove</button>';
            passkeysListEl.appendChild(li);
          });
          passkeysListEl.querySelectorAll('.remove-passkey').forEach((btn) => {
            btn.addEventListener('click', async () => {
              const id = btn.getAttribute('data-id');
              if (!id) return;
              if (!confirm('Remove this passkey? You will not be able to sign in with it.')) return;
              try {
                const encoded = encodeURIComponent(id);
                await fetch('/auth/webauthn/credentials/' + encoded, { method: 'DELETE', credentials: 'include' });
                loadProfile();
              } catch (err) {
                passkeysStatusEl.textContent = 'Failed to remove passkey';
                passkeysStatusEl.className = 'text-[11px] font-mono mt-2 text-red-300';
              }
            });
          });
        }
      }
    } catch (err) {
      window.location.href = '/admin/login.html';
    }
  }

  if (changePasswordForm) {
    changePasswordForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const current = currentPasswordInput.value;
      const newPw = newPasswordInput.value;
      const confirmPw = newPasswordConfirmInput.value;
      if (!current || !newPw) {
        setPasswordStatus('Current and new password are required', true);
        return;
      }
      if (newPw.length < 8) {
        setPasswordStatus('New password must be at least 8 characters', true);
        return;
      }
      if (newPw !== confirmPw) {
        setPasswordStatus('New passwords do not match', true);
        return;
      }
      try {
        setPasswordStatus('Updating…');
        await fetchJson('/auth/change-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ currentPassword: current, newPassword: newPw }),
        });
        setPasswordStatus('Password updated.', false);
        currentPasswordInput.value = '';
        newPasswordInput.value = '';
        newPasswordConfirmInput.value = '';
      } catch (err) {
        setPasswordStatus(err.message || 'Failed to update password', true);
      }
    });
  }

  if (setPasswordForm) {
    setPasswordForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const newPw = setNewPasswordInput.value;
      const confirmPw = setNewPasswordConfirmInput.value;
      if (!newPw) {
        setSetPasswordStatus('Password is required', true);
        return;
      }
      if (newPw.length < 8) {
        setSetPasswordStatus('Password must be at least 8 characters', true);
        return;
      }
      if (newPw !== confirmPw) {
        setSetPasswordStatus('Passwords do not match', true);
        return;
      }
      try {
        setSetPasswordStatus('Setting…');
        await fetchJson('/auth/set-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ newPassword: newPw }),
        });
        setSetPasswordStatus('Password set.', false);
        setNewPasswordInput.value = '';
        setNewPasswordConfirmInput.value = '';
        setPasswordSection.classList.add('hidden');
        if (changePasswordSection) changePasswordSection.classList.remove('hidden');
      } catch (err) {
        setSetPasswordStatus(err.message || 'Failed to set password', true);
      }
    });
  }

  if (accountLogoutLink) {
    accountLogoutLink.addEventListener('click', async (e) => {
      e.preventDefault();
      try {
        await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
      } catch (err) {}
      window.location.href = '/admin/login.html?logged_out=1';
    });
  }

  loadProfile();
})();

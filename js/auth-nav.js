/**
 * Universal auth nav: updates #auth-nav-container to show Login or Profile | Log out
 * based on /auth/info. Set <meta name="auth-api-base" content=""> for same-origin,
 * or content="https://admin.example.com" when auth is on another origin.
 */
(function () {
  function getAuthBase() {
    const meta = document.querySelector('meta[name="auth-api-base"]');
    const w = typeof window !== 'undefined' && window.AUTH_API_BASE;
    const base = (meta && meta.getAttribute('content')) || w || '';
    return String(base).trim().replace(/\/+$/, '');
  }

  const container = document.getElementById('auth-nav-container');
  if (!container) return;

  const base = getAuthBase();
  const prefix = base ? base : '';

  var loginUrl = prefix + '/admin/login.html';
  fetch(prefix + '/auth/info', { credentials: 'include' })
    .then(function (res) { return res.ok ? res.json() : Promise.reject(); })
    .then(function (data) {
      if (!data || !data.authenticated) {
        var link = container.querySelector('a');
        if (link) link.setAttribute('href', loginUrl);
        return;
      }
      container.innerHTML =
        '<a href="' + prefix + '/admin/profile.html" class="auth-nav-profile">Profile</a>' +
        ' <span class="auth-nav-sep" aria-hidden="true">|</span> ' +
        '<a href="#" id="auth-nav-logout" class="auth-nav-logout">Log out</a>';
      const logoutLink = document.getElementById('auth-nav-logout');
      if (logoutLink) {
        logoutLink.addEventListener('click', function (e) {
          e.preventDefault();
          fetch(prefix + '/auth/logout', { method: 'POST', credentials: 'include' })
            .then(function () {
              window.location.href = prefix + '/admin/login.html?logged_out=1';
            })
            .catch(function () {
              window.location.href = prefix + '/admin/login.html?logged_out=1';
            });
        });
      }
    })
    .catch(function () {});
})();

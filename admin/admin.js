async function fetchJson(url, options) {
  const res = await fetch(url, options);
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(text || `Request failed with ${res.status}`);
  }
  return res.json().catch(() => null);
}

const tableBody = document.getElementById('posts-table-body');
const form = document.getElementById('post-form');
const newPostBtn = document.getElementById('new-post-btn');
const deleteBtn = document.getElementById('delete-btn');
const statusEl = document.getElementById('status');

let currentSlug = null;

function setStatus(message, isError) {
  statusEl.textContent = message || '';
  statusEl.className = 'text-xs font-mono ' + (isError ? 'text-red-300' : 'text-zinc-400');
}

function formToPost() {
  const slug = form.slug.value.trim();
  const publishedOn = form.publishedOn.value ? form.publishedOn.value : '';
  const publishedLabel = form.publishedLabel.value.trim();
  const archivePath = (form.archivePath.value.trim() || `archive/${slug}.html`).replace(/^\/+/, '');

  return {
    slug,
    title: form.title.value.trim(),
    publishedOn,
    publishedLabel,
    hasArchive: true,
    archivePath,
    indexHtml: form.indexHtml.value,
    articleHtml: form.articleHtml.value || null,
  };
}

function populateForm(post) {
  currentSlug = post ? post.slug : null;

  form.slug.value = post ? post.slug : '';
  form.publishedOn.value = post && post.publishedOn ? post.publishedOn : '';
  form.publishedLabel.value = post && post.publishedLabel ? post.publishedLabel : '';
  form.title.value = post ? post.title : '';
  form.hasArchive.checked = post ? !!post.hasArchive : false;
  form.archivePath.value = post && post.archivePath ? post.archivePath : '';
  form.indexHtml.value = post && post.indexHtml ? post.indexHtml : '';
  form.articleHtml.value = post && post.articleHtml ? post.articleHtml : '';

  deleteBtn.classList.toggle('hidden', !post);
  setStatus(post ? `Editing "${post.slug}"` : 'Creating new post');
}

function openPostInNewTab(post) {
  if (post && post.hasArchive && post.archivePath) {
    const path = post.archivePath.replace(/^\/+/, '');
    const url = '/blog/' + path;
    window.open(url, '_blank');
  } else {
    // Fallback to main blog index if no archive page
    window.open('/blog/index.html', '_blank');
  }
}

function renderTable(posts) {
  tableBody.innerHTML = '';
  const sorted = posts.slice().sort((a, b) => {
    const da = a.publishedOn ? new Date(a.publishedOn) : 0;
    const db = b.publishedOn ? new Date(b.publishedOn) : 0;
    return db - da;
  });

  sorted.forEach((post) => {
    const tr = document.createElement('tr');
    tr.className = 'hover:bg-white/5 cursor-pointer';

    tr.innerHTML = `
      <td class="px-3 py-2 text-sm">${post.title || '<span class="text-zinc-500">Untitled</span>'}</td>
      <td class="px-3 py-2 text-xs font-mono text-zinc-400">${post.slug}</td>
      <td class="px-3 py-2 text-xs text-zinc-300">${post.publishedLabel || ''}</td>
      <td class="px-3 py-2 text-right text-xs text-zinc-400">${post.hasArchive ? 'Has archive' : ''}</td>
    `;

    tr.addEventListener('click', () => {
      populateForm(post);
    });

    tableBody.appendChild(tr);
  });
}

async function loadPosts() {
  try {
    setStatus('Loading posts…');
    const posts = await fetchJson('/api/posts');
    renderTable(posts || []);
    setStatus('Loaded posts');
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    setStatus('Failed to load posts', true);
  }
}

newPostBtn.addEventListener('click', () => {
  populateForm(null);
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const post = formToPost();

  if (!post.slug || !post.title) {
    setStatus('Slug and title are required', true);
    return;
  }

  try {
    setStatus('Saving…');
    if (currentSlug && currentSlug === post.slug) {
      await fetchJson(`/api/posts/${encodeURIComponent(currentSlug)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(post)
      });
    } else if (currentSlug && currentSlug !== post.slug) {
      // Slug changed: delete old and create new
      await fetch('/api/posts/' + encodeURIComponent(currentSlug), { method: 'DELETE' });
      await fetchJson('/api/posts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(post)
      });
    } else {
      await fetchJson('/api/posts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(post)
      });
    }

    currentSlug = post.slug;
    await loadPosts();
    setStatus('Saved', false);
    openPostInNewTab(post);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    setStatus('Failed to save post', true);
  }
});

deleteBtn.addEventListener('click', async () => {
  if (!currentSlug) return;
  const confirmed = window.confirm(`Delete post "${currentSlug}"? This cannot be undone.`);
  if (!confirmed) return;

  try {
    setStatus('Deleting…');
    await fetch('/api/posts/' + encodeURIComponent(currentSlug), { method: 'DELETE' });
    currentSlug = null;
    populateForm(null);
    await loadPosts();
    setStatus('Deleted', false);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    setStatus('Failed to delete post', true);
  }
});

const accountLogoutLink = document.getElementById('account-logout');
if (accountLogoutLink) {
  accountLogoutLink.addEventListener('click', async (e) => {
    e.preventDefault();
    try {
      await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin' });
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(err);
    }
    window.location.href = '/admin/login?logged_out=1';
  });
}

// Redirect to add-passkey if first login and no passkey yet
(async function init() {
  try {
    const me = await fetchJson('/auth/me', { credentials: 'include' });
    if (me && me.pendingPasskeyPrompt) {
      window.location.href = '/admin/add-passkey.html';
      return;
    }
  } catch (_) {
    // Not authenticated or error; loadPosts may 401 and redirect to login
  }
  loadPosts();
})();


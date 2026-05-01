'use strict';

/* ── Parts config ─────────────────────────────────────────────── */
const PARTS = [
  { file: 'docs/Part1-Introduction-KeyConcepts.md',               label: 'Introduction & Key Concepts',           num: 1, tags: ['Concept','Licensing','Policy Types'] },
  { file: 'docs/Part2-Policy-Templates-Rule-Options.md',          label: 'Policy Templates & Rule Options',        num: 2, tags: ['Templates','Rule Options','EKU','XML'] },
  { file: 'docs/Part3-AppID-Tagging-Managed-Installer.md',        label: 'AppID Tagging & Managed Installer',      num: 3, tags: ['AppID Tagging','Firewall','Managed Installer'] },
  { file: 'docs/Part4-Starter-Base-Policy-Lightly-Managed.md',    label: 'Starter Base Policy — Lightly Managed', num: 4, tags: ['SmartAppControl','PowerShell','Wizard'] },
  { file: 'docs/Part5-Base-Policy-Fully-Managed-Devices.md',      label: 'Base Policy — Fully Managed Devices',   num: 5, tags: ['Reference Scan','FilePublisher','Enforcement'] },
  { file: 'docs/Part6-Sign-Apply-Remove-Signed-Policies.md',      label: 'Sign, Apply & Remove Signed Policies',  num: 6, tags: ['Code Signing','SignTool','UEFI','Secure Boot'] },
  { file: 'docs/Part7-Maintaining-Policies-AzureDevOps-PowerShell.md', label: 'Maintaining Policies with Azure DevOps', num: 7, tags: ['Azure DevOps','OIDC','Pipeline','Graph API'] },
];

/* ── State ────────────────────────────────────────────────────── */
let currentPart   = 0;
let tocHeadings   = [];
let tocLinks      = [];
let scrollPending = false;

/* ── DOM refs ─────────────────────────────────────────────────── */
const sidebar       = document.getElementById('sidebar');
const backdrop      = document.getElementById('backdrop');
const main          = document.getElementById('main');
const content       = document.getElementById('content');
const tocPanel      = document.getElementById('toc-panel');
const tocNav        = document.getElementById('toc-nav');
const bcPart        = document.getElementById('bc-part');
const readTime      = document.getElementById('read-time');
const progressFill  = document.getElementById('progress-fill');
const partDots      = document.getElementById('part-dots');
const prevBtn       = document.getElementById('prev-part');
const nextBtn       = document.getElementById('next-part');
const navItems      = document.querySelectorAll('.nav-item');
const searchInput   = document.getElementById('search');

/* ── Marked: use v5+ API, no deprecated highlight callback ─────── */
marked.use({ gfm: true, breaks: false });

/* ── Sidebar open/close helpers ───────────────────────────────── */
function isMobile() { return window.innerWidth < 1024; }

function openSidebar() {
  sidebar.classList.add('open');
  backdrop.classList.add('visible');
  document.body.style.overflow = 'hidden';
}
function closeSidebar() {
  sidebar.classList.remove('open');
  backdrop.classList.remove('visible');
  document.body.style.overflow = '';
}
function toggleSidebar() {
  if (isMobile()) {
    sidebar.classList.contains('open') ? closeSidebar() : openSidebar();
  } else {
    const collapsed = sidebar.classList.toggle('collapsed');
    main.classList.toggle('full', collapsed);
  }
}

backdrop.addEventListener('click', closeSidebar);

/* ── Code block post-processing ─────────────────────────────────
   Called after content is injected into DOM.
   1. Runs hljs.highlightElement on each <code>
   2. Prepends a header bar with language + copy button
   ──────────────────────────────────────────────────────────────── */
function postProcessCode(container) {
  container.querySelectorAll('pre code').forEach(block => {
    const cls   = block.className || '';
    const match = cls.match(/language-([^\s"]+)/);
    const lang  = match ? match[1] : '';

    // Syntax highlight (safe — hljs loaded before this script)
    try { hljs.highlightElement(block); } catch (_) {}

    // Header bar
    const pre    = block.parentElement;
    const header = document.createElement('div');
    header.className = 'code-header';

    const langSpan       = document.createElement('span');
    langSpan.className   = 'code-lang';
    langSpan.textContent = lang || 'text';

    const btn       = document.createElement('button');
    btn.className   = 'copy-btn';
    btn.textContent = 'Copy';
    btn.addEventListener('click', () => {
      const text = block.innerText;
      (navigator.clipboard
        ? navigator.clipboard.writeText(text)
        : Promise.reject()
      ).catch(() => {
        // execCommand fallback
        const range = document.createRange();
        range.selectNodeContents(block);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        document.execCommand('copy');
        sel.removeAllRanges();
      }).finally(() => {
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
      });
    });

    header.appendChild(langSpan);
    header.appendChild(btn);
    pre.insertBefore(header, block);
  });
}

/* ── Table wrapper — enables horizontal scroll on mobile ─────── */
function wrapTables(container) {
  container.querySelectorAll('table').forEach(table => {
    if (table.parentElement.classList.contains('table-wrap')) return;
    const wrap = document.createElement('div');
    wrap.className = 'table-wrap';
    table.parentNode.insertBefore(wrap, table);
    wrap.appendChild(table);
  });
}

/* ── Reading time ─────────────────────────────────────────────── */
function calcReadTime(text) {
  const mins = Math.max(1, Math.round(text.trim().split(/\s+/).length / 200));
  return `${mins} min read`;
}

/* ── Part header card ─────────────────────────────────────────── */
function buildHeaderCard(part) {
  const tags = part.tags.map(t => `<span class="phc-tag">${t}</span>`).join('');
  return `
<div class="part-header-card">
  <div class="phc-num">${String(part.num).padStart(2, '0')}</div>
  <div class="phc-meta">
    <div class="phc-label">Mastering App Control for Business</div>
    <div class="phc-title">${part.label}</div>
    <div class="phc-tags">${tags}</div>
  </div>
</div>`;
}

/* ── Build per-page ToC ───────────────────────────────────────── */
function buildToc() {
  tocNav.innerHTML = '';
  tocLinks    = [];
  tocHeadings = Array.from(content.querySelectorAll('h2, h3'));

  if (tocHeadings.length === 0) { tocPanel.classList.add('hidden'); return; }
  tocPanel.classList.remove('hidden');

  tocHeadings.forEach((h, i) => {
    if (!h.id) {
      h.id = `s${i}-` + h.textContent.trim()
        .toLowerCase()
        .replace(/[^a-z0-9\s-]/g, '')
        .trim()
        .replace(/\s+/g, '-')
        .slice(0, 48);
    }

    const a = document.createElement('a');
    a.href        = '#' + h.id;
    a.textContent = h.textContent;
    if (h.tagName === 'H3') a.classList.add('toc-h3');

    a.addEventListener('click', e => {
      e.preventDefault();
      h.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });

    tocNav.appendChild(a);
    tocLinks.push(a);
  });

  updateActiveToc();
}

/* ── Active ToC tracking (scroll-driven, rAF-throttled) ─────── */
function updateActiveToc() {
  if (!tocHeadings.length) return;

  const OFFSET = parseInt(getComputedStyle(document.documentElement)
    .getPropertyValue('--topbar-h')) || 52;

  let activeIdx = 0;
  for (let i = 0; i < tocHeadings.length; i++) {
    if (tocHeadings[i].getBoundingClientRect().top - OFFSET - 8 <= 0) {
      activeIdx = i;
    }
  }

  tocLinks.forEach((l, i) => l.classList.toggle('active', i === activeIdx));

  // Keep active link visible inside toc panel
  const active = tocLinks[activeIdx];
  if (active && tocPanel.offsetParent !== null) {
    active.scrollIntoView({ block: 'nearest' });
  }
}

/* ── Scroll handler: progress bar + ToC ─────────────────────── */
window.addEventListener('scroll', () => {
  // Progress bar
  const el = document.documentElement;
  const pct = el.scrollHeight - el.clientHeight;
  progressFill.style.width = pct > 0 ? (el.scrollTop / pct * 100) + '%' : '0%';

  if (!scrollPending) {
    scrollPending = true;
    requestAnimationFrame(() => { updateActiveToc(); scrollPending = false; });
  }
}, { passive: true });

/* ── Dots ─────────────────────────────────────────────────────── */
function buildDots() {
  partDots.innerHTML = '';
  PARTS.forEach((p, i) => {
    const d = document.createElement('div');
    d.className   = 'dot' + (i === currentPart ? ' active' : '');
    d.title       = p.label;
    d.role        = 'tab';
    d.tabIndex    = 0;
    d.setAttribute('aria-label', `Part ${p.num}: ${p.label}`);
    d.addEventListener('click',   () => loadPart(i));
    d.addEventListener('keydown', e => { if (e.key === 'Enter') loadPart(i); });
    partDots.appendChild(d);
  });
}
function updateDots() {
  partDots.querySelectorAll('.dot').forEach((d, i) => d.classList.toggle('active', i === currentPart));
}

/* ── Sidebar nav items ───────────────────────────────────────── */
function updateNav() {
  navItems.forEach((item, i) => item.classList.toggle('active', i === currentPart));
}

/* ── Load a part ─────────────────────────────────────────────── */
async function loadPart(index) {
  if (index < 0 || index >= PARTS.length) return;
  currentPart = index;
  const part  = PARTS[index];

  // Reset
  content.classList.remove('loaded');
  content.innerHTML      = `<div id="loading"><div class="spinner"></div><p>Loading…</p></div>`;
  tocNav.innerHTML       = '';
  tocHeadings            = [];
  tocLinks               = [];
  progressFill.style.width = '0%';
  window.scrollTo({ top: 0 });

  updateNav();
  updateDots();
  bcPart.textContent = `Part ${part.num}`;
  prevBtn.disabled   = index === 0;
  nextBtn.disabled   = index === PARTS.length - 1;

  // Close mobile sidebar after selection
  if (isMobile()) closeSidebar();

  try {
    const res = await fetch(part.file);
    if (!res.ok) throw new Error(`HTTP ${res.status} — ${res.statusText}`);
    const raw = await res.text();

    // Strip front-matter
    const md = raw.replace(/^---[\s\S]*?---\s*\n/, '').trim();

    // Render markdown → HTML
    const html = marked.parse(md);

    content.innerHTML = buildHeaderCard(part) + html;
    content.classList.add('loaded');

    // Post-process
    postProcessCode(content);
    wrapTables(content);
    buildToc();
    readTime.textContent = calcReadTime(raw);

  } catch (err) {
    content.innerHTML = `
      <div style="text-align:center;padding:80px 20px;color:var(--text-muted)">
        <div style="font-size:48px;margin-bottom:16px">⚠️</div>
        <p style="font-size:16px;font-weight:600;margin-bottom:8px;color:var(--text)">Failed to load document</p>
        <p style="font-size:13px;margin-bottom:20px">${err.message}</p>
        <p style="font-size:12px;color:var(--text-dim)">
          Run a local server in the project folder:<br><br>
          <code style="background:var(--bg3);border:1px solid var(--border);padding:6px 14px;border-radius:6px;font-size:13px;display:inline-block">
            python3 -m http.server 8080
          </code>
        </p>
      </div>`;
  }
}

/* ── Search ───────────────────────────────────────────────────── */
searchInput.addEventListener('input', () => {
  const q = searchInput.value.toLowerCase().trim();
  navItems.forEach((item, i) => {
    const hit = !q
      || PARTS[i].label.toLowerCase().includes(q)
      || PARTS[i].tags.some(t => t.toLowerCase().includes(q));
    item.classList.toggle('hidden', !hit);
  });
});

/* ── Sidebar toggle button ────────────────────────────────────── */
document.getElementById('sidebar-toggle').addEventListener('click', toggleSidebar);

/* ── ToC toggle ───────────────────────────────────────────────── */
document.getElementById('toc-toggle').addEventListener('click', () => {
  tocPanel.classList.toggle('hidden');
});

/* ── Theme toggle ─────────────────────────────────────────────── */
const themeBtn = document.getElementById('theme-toggle');
themeBtn.addEventListener('click', () => {
  const next = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', next);
  themeBtn.textContent = next === 'light' ? '☀' : '☾';
  localStorage.setItem('acfb-theme', next);
  // Swap hljs theme
  const hljsLink = document.querySelector('link[href*="highlight.js"]');
  if (hljsLink) {
    hljsLink.href = next === 'light'
      ? 'https://cdn.jsdelivr.net/npm/highlight.js@11.9.0/styles/github.min.css'
      : 'https://cdn.jsdelivr.net/npm/highlight.js@11.9.0/styles/github-dark.min.css';
  }
});

/* ── Part nav buttons ─────────────────────────────────────────── */
prevBtn.addEventListener('click', () => loadPart(currentPart - 1));
nextBtn.addEventListener('click', () => loadPart(currentPart + 1));

/* ── Sidebar nav item clicks ──────────────────────────────────── */
navItems.forEach((item, i) => item.addEventListener('click', () => loadPart(i)));

/* ── Keyboard navigation ──────────────────────────────────────── */
document.addEventListener('keydown', e => {
  if (document.activeElement === searchInput) return;
  if (e.target.tagName === 'INPUT') return;
  if (e.key === 'ArrowRight' || e.key === 'j') loadPart(currentPart + 1);
  if (e.key === 'ArrowLeft'  || e.key === 'k') loadPart(currentPart - 1);
  if (e.key === 'Escape' && isMobile())         closeSidebar();
});

/* ── Resize: close backdrop if going desktop ──────────────────── */
window.addEventListener('resize', () => {
  if (!isMobile()) closeSidebar();
}, { passive: true });

/* ── Init ─────────────────────────────────────────────────────── */
(function init() {
  const theme = localStorage.getItem('acfb-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', theme);
  themeBtn.textContent = theme === 'light' ? '☀' : '☾';
  if (theme === 'light') {
    const hljsLink = document.querySelector('link[href*="highlight.js"]');
    if (hljsLink) hljsLink.href = 'https://cdn.jsdelivr.net/npm/highlight.js@11.9.0/styles/github.min.css';
  }

  buildDots();
  loadPart(0);
})();

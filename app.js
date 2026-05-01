'use strict';

/* ── Config ──────────────────────────────────────────────────── */
const PARTS = [
  { file: 'docs/Part1-Introduction-KeyConcepts.md',               label: 'Introduction & Key Concepts',           num: 1, tags: ['Concept','Licensing','Policy Types'] },
  { file: 'docs/Part2-Policy-Templates-Rule-Options.md',          label: 'Policy Templates & Rule Options',        num: 2, tags: ['Templates','Rule Options','EKU','XML'] },
  { file: 'docs/Part3-AppID-Tagging-Managed-Installer.md',        label: 'AppID Tagging & Managed Installer',      num: 3, tags: ['AppID Tagging','Firewall','Managed Installer'] },
  { file: 'docs/Part4-Starter-Base-Policy-Lightly-Managed.md',    label: 'Starter Base Policy — Lightly Managed', num: 4, tags: ['SmartAppControl','PowerShell','Wizard'] },
  { file: 'docs/Part5-Base-Policy-Fully-Managed-Devices.md',      label: 'Base Policy — Fully Managed Devices',   num: 5, tags: ['Reference Scan','FilePublisher','Enforcement'] },
  { file: 'docs/Part6-Sign-Apply-Remove-Signed-Policies.md',      label: 'Sign, Apply & Remove Signed Policies',  num: 6, tags: ['Code Signing','SignTool','UEFI','Secure Boot'] },
  { file: 'docs/Part7-Maintaining-Policies-AzureDevOps-PowerShell.md', label: 'Maintaining Policies with Azure DevOps', num: 7, tags: ['Azure DevOps','OIDC','Pipeline','Graph API'] },
];

/* ── State ───────────────────────────────────────────────────── */
let currentPart  = 0;
let tocHeadings  = [];
let tocLinks     = [];
let scrollTicking = false;

/* ── DOM refs ────────────────────────────────────────────────── */
const sidebar      = document.getElementById('sidebar');
const main         = document.getElementById('main');
const content      = document.getElementById('content');
const tocPanel     = document.getElementById('toc-panel');
const tocNav       = document.getElementById('toc-nav');
const bcPart       = document.getElementById('bc-part');
const readTime     = document.getElementById('read-time');
const progressFill = document.getElementById('progress-fill');
const partDots     = document.getElementById('part-dots');
const prevBtn      = document.getElementById('prev-part');
const nextBtn      = document.getElementById('next-part');
const navItems     = document.querySelectorAll('.nav-item');
const searchInput  = document.getElementById('search');

/* ── Marked config (v5+ API, no deprecated highlight option) ─── */
marked.use({ gfm: true, breaks: false });

/* ── Syntax highlight + copy buttons ────────────────────────── */
function postProcessCode(container) {
  container.querySelectorAll('pre code').forEach(block => {
    const cls   = block.className || '';
    const match = cls.match(/language-(\S+)/);
    const lang  = match ? match[1] : '';

    // hljs highlight
    try {
      if (typeof hljs !== 'undefined') hljs.highlightElement(block);
    } catch (e) { /* non-fatal */ }

    // Insert header bar above code
    const pre    = block.parentElement;
    const header = document.createElement('div');
    header.className = 'code-header';

    const langSpan = document.createElement('span');
    langSpan.className   = 'code-lang';
    langSpan.textContent = lang || 'text';

    const copyBtn = document.createElement('button');
    copyBtn.className   = 'copy-btn';
    copyBtn.textContent = 'Copy';
    copyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(block.innerText).then(() => {
        copyBtn.textContent = 'Copied!';
        copyBtn.classList.add('copied');
        setTimeout(() => { copyBtn.textContent = 'Copy'; copyBtn.classList.remove('copied'); }, 2000);
      }).catch(() => {
        // fallback
        const sel = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(block);
        sel.removeAllRanges();
        sel.addRange(range);
        document.execCommand('copy');
        sel.removeAllRanges();
        copyBtn.textContent = 'Copied!';
        setTimeout(() => { copyBtn.textContent = 'Copy'; }, 2000);
      });
    });

    header.appendChild(langSpan);
    header.appendChild(copyBtn);
    pre.insertBefore(header, block);
  });
}

/* ── Reading time ────────────────────────────────────────────── */
function calcReadTime(text) {
  const words = text.trim().split(/\s+/).length;
  return `${Math.max(1, Math.round(words / 200))} min read`;
}

/* ── Part header card ────────────────────────────────────────── */
function buildHeaderCard(part) {
  const tags = part.tags.map(t => `<span class="phc-tag">${t}</span>`).join('');
  return `<div class="part-header-card">
    <div class="phc-num">${String(part.num).padStart(2, '0')}</div>
    <div class="phc-meta">
      <div class="phc-label">Mastering App Control for Business</div>
      <div class="phc-title">${part.label}</div>
      <div class="phc-tags">${tags}</div>
    </div>
  </div>`;
}

/* ── Build per-page ToC dynamically ─────────────────────────── */
function buildToc() {
  tocNav.innerHTML = '';
  tocLinks    = [];
  tocHeadings = Array.from(content.querySelectorAll('h2, h3'));

  if (tocHeadings.length === 0) {
    tocPanel.classList.add('hidden');
    return;
  }
  tocPanel.classList.remove('hidden');

  tocHeadings.forEach((h, i) => {
    // Ensure each heading has a stable ID
    if (!h.id) {
      h.id = 'sec-' + i + '-' + h.textContent.trim()
        .toLowerCase()
        .replace(/[^a-z0-9\s]/g, '')
        .replace(/\s+/g, '-')
        .slice(0, 50);
    }

    const a = document.createElement('a');
    a.href = '#' + h.id;
    a.textContent = h.textContent;
    if (h.tagName === 'H3') a.classList.add('toc-h3');
    a.addEventListener('click', e => {
      e.preventDefault();
      h.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });

    tocNav.appendChild(a);
    tocLinks.push(a);
  });

  highlightActiveToc();
}

/* ── Scroll-driven ToC highlight ────────────────────────────── */
function highlightActiveToc() {
  if (tocHeadings.length === 0) return;

  const scrollY   = window.scrollY;
  const topOffset = 80; // topbar height + buffer

  let activeIdx = 0;
  for (let i = 0; i < tocHeadings.length; i++) {
    if (tocHeadings[i].getBoundingClientRect().top - topOffset <= 0) {
      activeIdx = i;
    }
  }

  tocLinks.forEach((link, i) => {
    link.classList.toggle('active', i === activeIdx);
  });

  // Scroll active link into view within toc panel
  const activeLink = tocLinks[activeIdx];
  if (activeLink) {
    activeLink.scrollIntoView({ block: 'nearest' });
  }
}

/* ── Reading progress + ToC highlight on scroll ─────────────── */
window.addEventListener('scroll', () => {
  // Progress bar
  const docEl = document.documentElement;
  const scrolled = docEl.scrollTop;
  const maxScroll = docEl.scrollHeight - docEl.clientHeight;
  progressFill.style.width = maxScroll > 0 ? (scrolled / maxScroll * 100) + '%' : '0%';

  // Throttle ToC highlight with rAF
  if (!scrollTicking) {
    window.requestAnimationFrame(() => {
      highlightActiveToc();
      scrollTicking = false;
    });
    scrollTicking = true;
  }
}, { passive: true });

/* ── Dots ────────────────────────────────────────────────────── */
function buildDots() {
  partDots.innerHTML = '';
  PARTS.forEach((p, i) => {
    const d = document.createElement('div');
    d.className = 'dot' + (i === currentPart ? ' active' : '');
    d.title = p.label;
    d.addEventListener('click', () => loadPart(i));
    partDots.appendChild(d);
  });
}

function updateDots() {
  partDots.querySelectorAll('.dot').forEach((d, i) => {
    d.classList.toggle('active', i === currentPart);
  });
}

/* ── Nav sidebar ─────────────────────────────────────────────── */
function updateNav() {
  navItems.forEach((item, i) => item.classList.toggle('active', i === currentPart));
}

/* ── Load a part ─────────────────────────────────────────────── */
async function loadPart(index) {
  if (index < 0 || index >= PARTS.length) return;
  currentPart = index;

  const part = PARTS[index];

  // Reset UI
  content.classList.remove('loaded');
  content.innerHTML = `<div id="loading"><div class="spinner"></div><p>Loading…</p></div>`;
  tocNav.innerHTML  = '';
  tocHeadings       = [];
  tocLinks          = [];
  progressFill.style.width = '0%';
  window.scrollTo({ top: 0 });

  updateNav();
  updateDots();
  bcPart.textContent = `Part ${part.num}`;
  prevBtn.disabled   = index === 0;
  nextBtn.disabled   = index === PARTS.length - 1;

  // Close sidebar on mobile
  if (window.innerWidth < 640) sidebar.classList.add('collapsed');

  try {
    const res = await fetch(part.file + '?v=' + Date.now());
    if (!res.ok) throw new Error(`HTTP ${res.status} — ${res.statusText}`);
    const raw = await res.text();

    // Strip markdown front-matter if present
    const cleaned = raw.replace(/^---[\s\S]*?---\n/, '').trim();

    // Parse markdown
    const html = marked.parse(cleaned);

    // Inject into DOM
    content.innerHTML = buildHeaderCard(part) + html;
    content.classList.add('loaded');

    // Post-process: syntax highlight + copy buttons
    postProcessCode(content);

    // Build dynamic per-page ToC
    buildToc();

    // Read time
    readTime.textContent = calcReadTime(raw);

  } catch (err) {
    content.innerHTML = `
      <div style="text-align:center;padding:80px 20px;color:var(--text-muted)">
        <div style="font-size:52px;margin-bottom:16px">⚠️</div>
        <p style="font-size:16px;font-weight:600;margin-bottom:8px">Failed to load document</p>
        <p style="font-size:13px;color:var(--text-dim);margin-bottom:4px">${err.message}</p>
        <p style="font-size:12px;color:var(--text-dim);margin-top:20px">
          Serve via a local HTTP server:<br>
          <code style="background:var(--code-bg);padding:4px 10px;border-radius:4px;font-size:12px">
            python3 -m http.server 8080
          </code>
        </p>
      </div>`;
  }
}

/* ── Search ──────────────────────────────────────────────────── */
searchInput.addEventListener('input', () => {
  const q = searchInput.value.toLowerCase().trim();
  navItems.forEach((item, i) => {
    const label = PARTS[i].label.toLowerCase();
    const tags  = PARTS[i].tags.join(' ').toLowerCase();
    item.classList.toggle('hidden', q.length > 0 && !label.includes(q) && !tags.includes(q));
  });
});

/* ── Sidebar toggle ──────────────────────────────────────────── */
document.getElementById('sidebar-toggle').addEventListener('click', () => {
  const collapsed = sidebar.classList.toggle('collapsed');
  main.classList.toggle('full', collapsed);
});

/* ── ToC toggle ──────────────────────────────────────────────── */
document.getElementById('toc-toggle').addEventListener('click', () => {
  tocPanel.classList.toggle('hidden');
});

/* ── Theme toggle ────────────────────────────────────────────── */
const themeBtn = document.getElementById('theme-toggle');
themeBtn.addEventListener('click', () => {
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  const next = isLight ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', next);
  themeBtn.textContent = next === 'light' ? '☀' : '☾';
  localStorage.setItem('acfb-theme', next);
});

/* ── Part nav buttons ────────────────────────────────────────── */
prevBtn.addEventListener('click', () => loadPart(currentPart - 1));
nextBtn.addEventListener('click', () => loadPart(currentPart + 1));

/* ── Sidebar nav items ───────────────────────────────────────── */
navItems.forEach((item, i) => item.addEventListener('click', () => loadPart(i)));

/* ── Keyboard nav ────────────────────────────────────────────── */
document.addEventListener('keydown', e => {
  if (document.activeElement === searchInput) return;
  if (e.key === 'ArrowRight' || e.key === 'j') loadPart(currentPart + 1);
  if (e.key === 'ArrowLeft'  || e.key === 'k') loadPart(currentPart - 1);
});

/* ── Init ────────────────────────────────────────────────────── */
(function init() {
  const saved = localStorage.getItem('acfb-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  themeBtn.textContent = saved === 'light' ? '☀' : '☾';

  buildDots();
  loadPart(0);
})();

'use strict';

/* ── Config ──────────────────────────────────────────────────── */
const PARTS = [
  { file: 'docs/Part1-Introduction-KeyConcepts.md',               label: 'Introduction & Key Concepts',              num: 1, tags: ['Concept','Licensing','Policy Types'] },
  { file: 'docs/Part2-Policy-Templates-Rule-Options.md',          label: 'Policy Templates & Rule Options',           num: 2, tags: ['Templates','Rule Options','EKU','XML'] },
  { file: 'docs/Part3-AppID-Tagging-Managed-Installer.md',        label: 'AppID Tagging & Managed Installer',         num: 3, tags: ['AppID Tagging','Firewall','Managed Installer'] },
  { file: 'docs/Part4-Starter-Base-Policy-Lightly-Managed.md',    label: 'Starter Base Policy — Lightly Managed',    num: 4, tags: ['SmartAppControl','PowerShell','Wizard','Audit Mode'] },
  { file: 'docs/Part5-Base-Policy-Fully-Managed-Devices.md',      label: 'Base Policy — Fully Managed Devices',      num: 5, tags: ['Reference Scan','FilePublisher','Enforcement'] },
  { file: 'docs/Part6-Sign-Apply-Remove-Signed-Policies.md',      label: 'Sign, Apply & Remove Signed Policies',     num: 6, tags: ['Code Signing','SignTool','UEFI','Secure Boot'] },
  { file: 'docs/Part7-Maintaining-Policies-AzureDevOps-PowerShell.md', label: 'Maintaining Policies with Azure DevOps', num: 7, tags: ['Azure DevOps','OIDC','Pipeline','Graph API'] },
];

/* ── State ───────────────────────────────────────────────────── */
let currentPart = 0;
let tocLinks     = [];
let tocObserver  = null;

/* ── DOM refs ────────────────────────────────────────────────── */
const sidebar       = document.getElementById('sidebar');
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

/* ── Marked config ───────────────────────────────────────────── */
marked.setOptions({
  gfm: true,
  breaks: false,
  highlight: (code, lang) => {
    if (lang && hljs.getLanguage(lang)) {
      return hljs.highlight(code, { language: lang }).value;
    }
    return hljs.highlightAuto(code).value;
  },
});

/* ── Markdown → HTML with post-processing ────────────────────── */
function renderMarkdown(raw) {
  // Parse
  let html = marked.parse(raw);

  // Inject code-header bars with copy button
  html = html.replace(
    /<pre><code(?: class="language-([^"]*)")?>([\s\S]*?)<\/code><\/pre>/g,
    (_, lang, code) => {
      const label = lang || 'text';
      const escaped = code.replace(/</g, '&lt;').replace(/>/g, '&gt;');
      return `
<pre>
  <div class="code-header">
    <span class="code-lang">${label}</span>
    <button class="copy-btn" onclick="copyCode(this)">Copy</button>
  </div>
  <code class="${lang ? 'language-' + lang : ''}">${code}</code>
</pre>`;
    }
  );

  return html;
}

/* ── Copy code ───────────────────────────────────────────────── */
window.copyCode = function (btn) {
  const code = btn.closest('pre').querySelector('code');
  navigator.clipboard.writeText(code.innerText).then(() => {
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
  });
};

/* ── Reading time ────────────────────────────────────────────── */
function calcReadTime(text) {
  const words = text.trim().split(/\s+/).length;
  const mins = Math.max(1, Math.round(words / 200));
  return `${mins} min read`;
}

/* ── Build header card ───────────────────────────────────────── */
function buildHeaderCard(part) {
  return `<div class="part-header-card">
    <div class="phc-num">${String(part.num).padStart(2,'0')}</div>
    <div class="phc-meta">
      <div class="phc-label">Mastering App Control for Business</div>
      <div class="phc-title">${part.label}</div>
      <div class="phc-tags">${part.tags.map(t => `<span class="phc-tag">${t}</span>`).join('')}</div>
    </div>
  </div>`;
}

/* ── Build ToC from headings ─────────────────────────────────── */
function buildToc() {
  const headings = content.querySelectorAll('h2, h3');
  tocNav.innerHTML = '';
  tocLinks = [];

  if (headings.length === 0) {
    tocPanel.classList.add('hidden');
    return;
  }
  tocPanel.classList.remove('hidden');

  headings.forEach((h, i) => {
    if (!h.id) {
      h.id = 'h-' + i + '-' + h.textContent.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
    }
    const a = document.createElement('a');
    a.href   = '#' + h.id;
    a.textContent = h.textContent;
    if (h.tagName === 'H3') a.classList.add('toc-h3');
    tocNav.appendChild(a);
    tocLinks.push(a);
  });

  // Observe headings
  if (tocObserver) tocObserver.disconnect();
  tocObserver = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        tocLinks.forEach(l => l.classList.remove('active'));
        const active = tocLinks.find(l => l.getAttribute('href') === '#' + entry.target.id);
        if (active) active.classList.add('active');
      }
    });
  }, { rootMargin: '-20% 0px -70% 0px' });

  headings.forEach(h => tocObserver.observe(h));
}

/* ── Reading progress ────────────────────────────────────────── */
function updateProgress() {
  const el   = document.documentElement;
  const body = document.body;
  const top  = el.scrollTop  || body.scrollTop;
  const h    = (el.scrollHeight || body.scrollHeight) - el.clientHeight;
  progressFill.style.width = h > 0 ? (top / h * 100) + '%' : '0%';
}
window.addEventListener('scroll', updateProgress, { passive: true });

/* ── Dots ─────────────────────────────────────────────────────── */
function buildDots() {
  partDots.innerHTML = '';
  PARTS.forEach((_, i) => {
    const d = document.createElement('div');
    d.className = 'dot' + (i === currentPart ? ' active' : '');
    d.title = PARTS[i].label;
    d.addEventListener('click', () => loadPart(i));
    partDots.appendChild(d);
  });
}
function updateDots() {
  partDots.querySelectorAll('.dot').forEach((d, i) => {
    d.classList.toggle('active', i === currentPart);
  });
}

/* ── Nav items ───────────────────────────────────────────────── */
function updateNav() {
  navItems.forEach((item, i) => {
    item.classList.toggle('active', i === currentPart);
  });
}

/* ── Load a part ──────────────────────────────────────────────── */
async function loadPart(index) {
  if (index < 0 || index >= PARTS.length) return;
  currentPart = index;

  const part = PARTS[index];

  // UI resets
  content.classList.remove('loaded');
  content.innerHTML = '<div id="loading"><div class="spinner"></div><p>Loading document…</p></div>';
  window.scrollTo({ top: 0, behavior: 'smooth' });
  progressFill.style.width = '0%';

  // Nav updates
  updateNav();
  updateDots();
  bcPart.textContent = `Part ${part.num}`;
  prevBtn.disabled = index === 0;
  nextBtn.disabled = index === PARTS.length - 1;

  // Close sidebar on mobile
  if (window.innerWidth < 640) sidebar.classList.add('collapsed');

  try {
    const res = await fetch(part.file);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const raw = await res.text();

    // Strip YAML-style frontmatter if any
    const cleaned = raw.replace(/^---[\s\S]*?---\n/, '');

    // Render
    const html = renderMarkdown(cleaned);

    content.innerHTML = buildHeaderCard(part) + html;
    content.classList.add('loaded');

    // Highlight all code blocks
    content.querySelectorAll('pre code').forEach(block => {
      hljs.highlightElement(block);
    });

    // Build ToC
    buildToc();

    // Read time
    readTime.textContent = calcReadTime(raw);

  } catch (err) {
    content.innerHTML = `
      <div style="text-align:center;padding:60px 0;color:var(--text-muted)">
        <div style="font-size:48px;margin-bottom:16px">⚠️</div>
        <p style="font-size:15px;margin-bottom:8px">Failed to load document</p>
        <p style="font-size:13px;color:var(--text-dim)">${err.message}</p>
        <p style="font-size:12px;color:var(--text-dim);margin-top:16px">
          Open via a local server or browser with file:// access.
        </p>
      </div>`;
  }
}

/* ── Search ───────────────────────────────────────────────────── */
searchInput.addEventListener('input', () => {
  const q = searchInput.value.toLowerCase().trim();
  navItems.forEach((item, i) => {
    const label = PARTS[i].label.toLowerCase();
    const tags  = PARTS[i].tags.join(' ').toLowerCase();
    item.classList.toggle('hidden', q && !label.includes(q) && !tags.includes(q));
  });
});

/* ── Sidebar toggle ───────────────────────────────────────────── */
document.getElementById('sidebar-toggle').addEventListener('click', () => {
  sidebar.classList.toggle('collapsed');
  main.classList.toggle('full', sidebar.classList.contains('collapsed'));
});

/* ── ToC toggle ───────────────────────────────────────────────── */
document.getElementById('toc-toggle').addEventListener('click', () => {
  tocPanel.classList.toggle('hidden');
});

/* ── Theme toggle ─────────────────────────────────────────────── */
document.getElementById('theme-toggle').addEventListener('click', () => {
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  document.documentElement.setAttribute('data-theme', isLight ? 'dark' : 'light');
  document.getElementById('theme-toggle').textContent = isLight ? '☾' : '☀';
  localStorage.setItem('acfb-theme', isLight ? 'dark' : 'light');
});

/* ── Part navigation buttons ──────────────────────────────────── */
prevBtn.addEventListener('click', () => loadPart(currentPart - 1));
nextBtn.addEventListener('click', () => loadPart(currentPart + 1));

/* ── Nav item clicks ──────────────────────────────────────────── */
navItems.forEach((item, i) => {
  item.addEventListener('click', () => loadPart(i));
});

/* ── Keyboard navigation ──────────────────────────────────────── */
document.addEventListener('keydown', e => {
  if (e.target === searchInput) return;
  if (e.key === 'ArrowRight' || e.key === 'l') loadPart(currentPart + 1);
  if (e.key === 'ArrowLeft'  || e.key === 'h') loadPart(currentPart - 1);
});

/* ── Init ─────────────────────────────────────────────────────── */
(function init() {
  // Restore theme
  const saved = localStorage.getItem('acfb-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  document.getElementById('theme-toggle').textContent = saved === 'light' ? '☀' : '☾';

  // Build dots
  buildDots();

  // Load first part (or from URL hash)
  const hash = window.location.hash;
  const partIndex = hash ? parseInt(hash.replace('#part','')) - 1 : 0;
  loadPart(Math.max(0, Math.min(PARTS.length - 1, partIndex || 0)));
})();

# App Control for Business — Complete Reference Series

Corporate-ready documentation for **Microsoft App Control for Business (ACfB)**, formerly known as Windows Defender Application Control (WDAC). Compiled by **Anubhav Gain** from source material by Patrick Seltmann at [ctrlshiftenter.cloud](https://ctrlshiftenter.cloud).

## Live Viewer

Open `index.html` via a local server:

```bash
python3 -m http.server 8080
# then visit http://localhost:8080
```

Features: dark/light theme · part search · reading progress · syntax-highlighted code · copy buttons · keyboard navigation (`←` / `→`).

## Series Overview

| Part | Topic |
|------|-------|
| 01 | Introduction & Key Concepts |
| 02 | Policy Templates & Rule Options |
| 03 | Application ID Tagging & Managed Installer |
| 04 | Starter Base Policy — Lightly Managed Devices |
| 05 | Base Policy — Fully Managed Devices |
| 06 | Sign, Apply & Remove Signed Policies |
| 07 | Maintaining Policies with Azure DevOps (or PowerShell) |

## Structure

```
appControlBusiness/
├── index.html       ← viewer entry point
├── style.css
├── app.js
└── docs/
    └── Part*.md     ← all 7 reference documents
```

## Tech

HTML · CSS · Vanilla JS · [marked.js](https://marked.js.org) · [highlight.js](https://highlightjs.org)

---

*Source: ctrlshiftenter.cloud — Patrick Seltmann. For organizational reference use.*

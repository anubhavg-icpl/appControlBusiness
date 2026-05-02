'use strict';

/* ── Parts config ─────────────────────────────────────────────── */
const BASE_URL = 'https://anubhavg-icpl.github.io/appControlBusiness/';
const SITE_NAME = 'Mastering App Control for Business';

const PARTS = [
  {
    file:  'docs/Part1-Introduction-KeyConcepts.md',
    label: 'Introduction & Key Concepts',
    num:   1,
    tags:  ['Concept','Licensing','Policy Types'],
    desc:  'Introduction to Microsoft App Control for Business (WDAC): key concepts, use cases, licensing requirements, policy formats, and core terminology including base, supplemental, and AppID tagging policies.',
    keywords: 'App Control for Business introduction, WDAC concepts, application allowlisting, policy types, base policy, supplemental policy, AppID tagging',
  },
  {
    file:  'docs/Part2-Policy-Templates-Rule-Options.md',
    label: 'Policy Templates & Rule Options',
    num:   2,
    tags:  ['Templates','Rule Options','EKU','XML'],
    desc:  'Deep dive into ACfB policy templates (DefaultWindows, AllowMicrosoft, SmartAppControl), all 21 security rule options, EKU encoding, file rules, signer rules, signing scenarios, and complete XML examples.',
    keywords: 'WDAC policy templates, rule options, EKU, Enhanced Key Usage, signer rules, file rules, signing scenarios, UMCI, KMCI, WHQL',
  },
  {
    file:  'docs/Part3-AppID-Tagging-Managed-Installer.md',
    label: 'AppID Tagging & Managed Installer',
    num:   3,
    tags:  ['AppID Tagging','Firewall','Managed Installer'],
    desc:  'How to create Application ID Tagging Policies, integrate them with Windows Firewall for process-scoped outbound rules, and configure Intune as a Managed Installer for automatic application trust.',
    keywords: 'AppID tagging, Application ID tagging policy, Windows Firewall, managed installer, Intune managed installer, outbound firewall rules, WDAC tagging',
  },
  {
    file:  'docs/Part4-Starter-Base-Policy-Lightly-Managed.md',
    label: 'Starter Base Policy — Lightly Managed',
    num:   4,
    tags:  ['SmartAppControl','PowerShell','Wizard'],
    desc:  'Step-by-step guide to creating a starter ACfB base policy for lightly managed devices using the SmartAppControl template, PowerShell cmdlets, and the App Control Policy Wizard, with audit mode validation.',
    keywords: 'SmartAppControl template, WDAC starter policy, lightly managed devices, audit mode, Set-RuleOption, App Control Policy Wizard, Intelligent Security Graph',
  },
  {
    file:  'docs/Part5-Base-Policy-Fully-Managed-Devices.md',
    label: 'Base Policy — Fully Managed Devices',
    num:   5,
    tags:  ['Reference Scan','FilePublisher','Enforcement'],
    desc:  'Creating a production App Control for Business base policy from a reference system scan using New-CIPolicy, configuring FilePublisher rules, fallback level comparison, and enforcement mode user experience.',
    keywords: 'New-CIPolicy, FilePublisher rule, fully managed devices, reference system scan, WDAC enforcement, policy from scratch, fallback rules, citool',
  },
  {
    file:  'docs/Part6-Sign-Apply-Remove-Signed-Policies.md',
    label: 'Sign, Apply & Remove Signed Policies',
    num:   6,
    tags:  ['Code Signing','SignTool','UEFI','Secure Boot'],
    desc:  'Complete guide to signing App Control for Business policies with code signing certificates using SignTool.exe, applying signed policies via CiTool, UEFI Secure Boot anti-tampering behavior, and safely removing signed policies.',
    keywords: 'WDAC signed policy, SignTool.exe, code signing certificate, UEFI Secure Boot, remove signed policy, CiTool, anti-tampering, UpdatePolicySigners',
  },
  {
    file:  'docs/Part7-Maintaining-Policies-AzureDevOps-PowerShell.md',
    label: 'Maintaining Policies with Azure DevOps',
    num:   7,
    tags:  ['Azure DevOps','OIDC','Pipeline','Graph API'],
    desc:  'Automating App Control for Business policy signing and Intune deployment using Azure DevOps Pipelines with Workload Identity Federation (OIDC), Microsoft Graph API, and a PowerShell script with version-based update logic.',
    keywords: 'Azure DevOps WDAC, Intune Graph API, policy automation, workload identity federation, OIDC pipeline, Publish-ACFBPolicy.ps1, policy versioning',
  },
  {
    file:  'docs/Part8-AppLocker-Option13-Selective-MSI-Allowlisting.md',
    label: 'AppLocker, Option 13 & Selective MSI Allowlisting',
    num:   8,
    tags:  ['AppLocker','Option 13','Managed Installer','Supplemental Policy','Selective Allowlist'],
    desc:  'Deep-dive into AppLocker ManagedInstaller rule collection, AppLockerFltr.sys kernel driver, KERNEL.SMARTLOCKER.ORIGINCLAIM EA stamping, and WDAC Option 13. Compares blanket MI trust against selective MSI allowlisting via per-app FilePublisher and Hash supplemental policies — with full end-to-end PoC workflow.',
    keywords: 'AppLocker managed installer, Option 13, WDAC supplemental policy, FilePublisher rule, KERNEL.SMARTLOCKER.ORIGINCLAIM, AppLockerFltr, selective MSI allowlisting, approved-apps.json, EA tagging, ci.dll evaluation',
  },

  // ── Rule Options Reference (indices 8–29) ────────────────────
  {
    file:  'docs/rule-options/Option-00-UMCI.md',
    label: 'Option 00 — UMCI',
    num:   'opt-00',
    category: 'rule-option',
    tags:  ['UMCI','User Mode CI','Enforcement'],
    desc:  'User Mode Code Integrity — the master enforcement switch. Controls whether user-space applications are subject to App Control policy evaluation via ci.dll.',
    keywords: 'UMCI, User Mode Code Integrity, Option 0, WDAC enforcement, user mode policy, ci.dll',
  },
  {
    file:  'docs/rule-options/Option-01-Boot-Menu-Protection.md',
    label: 'Option 01 — Boot Menu Protection',
    num:   'opt-01',
    category: 'rule-option',
    tags:  ['Boot Protection','UEFI','Secure Boot'],
    desc:  'Disables the F10 boot options menu when Secure Boot is active, preventing attackers from modifying boot configuration to bypass WDAC policy at startup.',
    keywords: 'Boot Menu Protection, Option 1, WDAC boot, Secure Boot, F10 boot menu, UEFI boot bypass',
  },
  {
    file:  'docs/rule-options/Option-02-WHQL.md',
    label: 'Option 02 — Required WHQL Drivers',
    num:   'opt-02',
    category: 'rule-option',
    tags:  ['WHQL','Driver Signing','Kernel Mode','BYOVD'],
    desc:  'All kernel-mode drivers must be WHQL-signed. Prevents unsigned or self-signed kernel drivers from loading — critical defense against BYOVD (Bring Your Own Vulnerable Driver) attacks.',
    keywords: 'WHQL Required, Option 2, kernel driver signing, BYOVD, bring your own vulnerable driver, driver certification',
  },
  {
    file:  'docs/rule-options/Option-03-Audit-Mode.md',
    label: 'Option 03 — Audit Mode',
    num:   'opt-03',
    category: 'rule-option',
    tags:  ['Audit Mode','Event Log','3076','3077'],
    desc:  'Runs WDAC in audit-only mode — blocked executions are logged to the CodeIntegrity event log (Event IDs 3076/3077) but not actually blocked. Essential for policy development and baselining.',
    keywords: 'Audit Mode, Option 3, WDAC audit, Event ID 3076, Event ID 3077, CodeIntegrity event log, policy testing',
  },
  {
    file:  'docs/rule-options/Option-04-Flight-Signing.md',
    label: 'Option 04 — Flight Signing',
    num:   'opt-04',
    category: 'rule-option',
    tags:  ['Flight Signing','Windows Insider','Pre-release'],
    desc:  'Allows files signed with the Microsoft flight root certificate to run — required on Windows Insider / preview builds. Must be disabled on production systems.',
    keywords: 'Flight Signing, Option 4, Windows Insider, pre-release certificate, flight root, preview build',
  },
  {
    file:  'docs/rule-options/Option-05-Inherit-Default-Policy.md',
    label: 'Option 05 — Inherit Default Policy',
    num:   'opt-05',
    category: 'rule-option',
    tags:  ['Policy Inheritance','Default Policy'],
    desc:  'Controls whether the base policy inherits default built-in allow rules from the Windows base policy. Understanding when inheritance applies vs. when explicit rules are required.',
    keywords: 'Inherit Default Policy, Option 5, WDAC policy inheritance, base policy inheritance, default Windows policy',
  },
  {
    file:  'docs/rule-options/Option-06-Unsigned-System-Integrity-Policy.md',
    label: 'Option 06 — Unsigned SI Policy',
    num:   'opt-06',
    category: 'rule-option',
    tags:  ['Unsigned Policy','Policy Signing','Anti-Tamper'],
    desc:  'When omitted, WDAC enforces that the base policy binary must itself be code-signed — hardening against offline policy tampering. Requires a code-signing certificate for policy deployment.',
    keywords: 'Unsigned System Integrity Policy, Option 6, policy signing, unsigned WDAC policy, policy tamper protection',
  },
  {
    file:  'docs/rule-options/Option-07-Debug-Policy-Augmented.md',
    label: 'Option 07 — Debug Policy Augmented',
    num:   'opt-07',
    category: 'rule-option',
    tags:  ['Debug Mode','Kernel Debugging','WinDbg'],
    desc:  'When not set, enabling kernel debugging does NOT bypass WDAC enforcement. If set, kernel debug mode augments (relaxes) the policy — avoid on production machines.',
    keywords: 'Debug Policy Augmented, Option 7, kernel debug mode, WinDbg WDAC bypass, debug mode enforcement',
  },
  {
    file:  'docs/rule-options/Option-08-EV-Signers.md',
    label: 'Option 08 — Required EV Signers',
    num:   'opt-08',
    category: 'rule-option',
    tags:  ['EV Signing','Extended Validation','Certificate'],
    desc:  'Requires drivers to be signed with an Extended Validation (EV) certificate — stronger than standard code signing. Eliminates low-cost certificates from the trusted driver pool.',
    keywords: 'Required EV Signers, Option 8, Extended Validation certificate, EV code signing, driver signing requirements',
  },
  {
    file:  'docs/rule-options/Option-09-Advanced-Boot-Options-Menu.md',
    label: 'Option 09 — Advanced Boot Options Menu',
    num:   'opt-09',
    category: 'rule-option',
    tags:  ['Boot Options','F8 Key','Safe Mode','Boot Bypass'],
    desc:  'Prevents users from accessing the F8 Advanced Boot Options menu — blocks booting to safe mode or disabling driver signature enforcement to bypass WDAC enforcement.',
    keywords: 'Advanced Boot Options Menu, Option 9, F8 boot menu, safe mode bypass, disable driver enforcement, boot bypass',
  },
  {
    file:  'docs/rule-options/Option-10-Boot-Audit-on-Failure.md',
    label: 'Option 10 — Boot Audit on Failure',
    num:   'opt-10',
    category: 'rule-option',
    tags:  ['Boot Audit','Failure Recovery','Resilience'],
    desc:  'If the WDAC policy fails to load at boot (e.g., corrupted policy file), the system boots to audit mode rather than hard-blocking. Prevents boot-loops from policy errors.',
    keywords: 'Boot Audit on Failure, Option 10, WDAC boot failure, audit mode fallback, policy load failure, boot-loop prevention',
  },
  {
    file:  'docs/rule-options/Option-11-Script-Enforcement-Disabled.md',
    label: 'Option 11 — Disable Script Enforcement',
    num:   'opt-11',
    category: 'rule-option',
    tags:  ['Script Enforcement','PowerShell CLM','VBScript','LOLBin'],
    desc:  'Confusingly named: when NOT set, script enforcement IS active — PowerShell enters Constrained Language Mode and VBScript/JScript are policy-controlled. Critical for LOLBin defences.',
    keywords: 'Disable Script Enforcement, Option 11, PowerShell Constrained Language Mode, CLM, VBScript enforcement, script policy, WDAC scripts',
  },
  {
    file:  'docs/rule-options/Option-12-Enforce-Store-Applications.md',
    label: 'Option 12 — Enforce Store Apps',
    num:   'opt-12',
    category: 'rule-option',
    tags:  ['Store Apps','UWP','MSIX','Package Family Name'],
    desc:  'Extends WDAC enforcement to UWP/Store/MSIX applications. Without explicit Package Family Name rules, enabling this can block the Windows Store and built-in inbox apps.',
    keywords: 'Enforce Store Applications, Option 12, UWP enforcement, MSIX policy, Windows Store WDAC, Package Family Name',
  },
  {
    file:  'docs/rule-options/Option-13-Managed-Installer.md',
    label: 'Option 13 — Managed Installer',
    num:   'opt-13',
    category: 'rule-option',
    tags:  ['Managed Installer','AppLocker','EA','AppLockerFltr'],
    desc:  'Trusts files written by AppLocker-designated Managed Installer processes (SCCM, Intune). Uses KERNEL.SMARTLOCKER.ORIGINCLAIM NTFS Extended Attribute stamped by the AppLockerFltr.sys kernel driver.',
    keywords: 'Managed Installer, Option 13, AppLocker managed installer, KERNEL.SMARTLOCKER.ORIGINCLAIM, AppLockerFltr, EA tagging, SCCM trust, Intune trust',
  },
  {
    file:  'docs/rule-options/Option-14-ISG-Authorization.md',
    label: 'Option 14 — ISG Authorization',
    num:   'opt-14',
    category: 'rule-option',
    tags:  ['ISG','Intelligent Security Graph','Cloud Trust','Reputation'],
    desc:  'Trusts files with high reputation from Microsoft Intelligent Security Graph cloud service. Queries sp.oci.microsoft.com; caches result as NTFS EA (byte[4]=0x01). Requires internet connectivity.',
    keywords: 'ISG Authorization, Option 14, Intelligent Security Graph, cloud trust, file reputation, sp.oci.microsoft.com, WDAC cloud',
  },
  {
    file:  'docs/rule-options/Option-15-Invalidate-EAs-on-Reboot.md',
    label: 'Option 15 — Invalidate EAs on Reboot',
    num:   'opt-15',
    category: 'rule-option',
    tags:  ['EA Invalidation','Reboot','ISG Cache','MI Cache'],
    desc:  'Clears all Managed Installer and ISG Extended Attribute trust cache entries on every reboot, forcing fresh evaluation. Prevents stale trust from persisting after policy changes.',
    keywords: 'Invalidate EAs on Reboot, Option 15, EA cache flush, MI trust reset, ISG cache invalidation, WDAC reboot policy',
  },
  {
    file:  'docs/rule-options/Option-16-Update-Policy-No-Reboot.md',
    label: 'Option 16 — Update Policy No Reboot',
    num:   'opt-16',
    category: 'rule-option',
    tags:  ['Hot Reload','Policy Update','CiTool'],
    desc:  'Allows policy updates to take effect without a reboot via CiTool.exe --update-policy. Enables live policy deployment in managed environments — essential for supplemental policy workflows.',
    keywords: 'Update Policy No Reboot, Option 16, hot policy reload, CiTool update policy, live WDAC deployment, no reboot policy',
  },
  {
    file:  'docs/rule-options/Option-17-Allow-Supplemental-Policies.md',
    label: 'Option 17 — Allow Supplemental Policies',
    num:   'opt-17',
    category: 'rule-option',
    tags:  ['Supplemental Policy','Policy Architecture','Multi-Policy'],
    desc:  'Allows the base policy to accept linked supplemental policies. Supplementals can only ADD trust — never restrict. Enables per-app and per-department trust extensions without modifying the base.',
    keywords: 'Allow Supplemental Policies, Option 17, supplemental policy, base policy architecture, SupplementsBasePolicyID, WDAC multi-policy',
  },
  {
    file:  'docs/rule-options/Option-18-Disable-Runtime-FilePath-Rule-Protection.md',
    label: 'Option 18 — Disable FilePath Protection',
    num:   'opt-18',
    category: 'rule-option',
    tags:  ['FilePath Rules','Runtime Protection','Symlink Attack'],
    desc:  'When not set, FilePath rules are protected at runtime against filesystem redirection. If set, junctions and symlinks can be used to spoof FilePath-based trust — avoid on production.',
    keywords: 'Disable Runtime FilePath Protection, Option 18, FilePath rule security, symlink bypass, junction attack, WDAC path rules',
  },
  {
    file:  'docs/rule-options/Option-19-Dynamic-Code-Security.md',
    label: 'Option 19 — Dynamic Code Security',
    num:   'opt-19',
    category: 'rule-option',
    tags:  ['Dynamic Code','JIT','Reflection.Emit','Always Enforced'],
    desc:  'Extends WDAC enforcement to dynamically generated code: JIT, Reflection.Emit, Assembly.Load(byte[]), Expression.Compile. Always enforced — audit mode does NOT suppress this option.',
    keywords: 'Dynamic Code Security, Option 19, JIT compilation WDAC, Reflection.Emit policy, Assembly.Load byte array, dynamic code enforcement, always enforced',
  },
  {
    file:  'docs/rule-options/Option-20-Revoked-Expired-As-Unsigned.md',
    label: 'Option 20 — Revoked/Expired as Unsigned',
    num:   'opt-20',
    category: 'rule-option',
    tags:  ['Revoked Certificates','Expired Certs','PKI','Lifetime Signing EKU'],
    desc:  'Files signed with revoked or expired certificates are treated as unsigned rather than cert-trusted. Enables PKI governance for enterprise CA rollover; uses Lifetime Signing EKU (OID 1.3.6.1.4.1.311.10.3.13).',
    keywords: 'Revoked Expired as Unsigned, Option 20, revoked certificate WDAC, expired code signing, Lifetime Signing EKU, OID 1.3.6.1.4.1.311.10.3.13',
  },
  {
    file:  'docs/rule-options/Option-DevMode-Dynamic-Code-Trust.md',
    label: 'Developer Mode — Dynamic Code Trust',
    num:   'opt-dev',
    category: 'rule-option',
    tags:  ['Developer Mode','Dynamic Code Trust','MDM CSP'],
    desc:  'Trusts dynamically generated code when Windows Developer Mode is active. Requires BOTH this policy option AND Developer Mode system state. Controlled via AllowDeveloperUnlock MDM CSP.',
    keywords: 'Developer Mode Dynamic Code Trust, WDAC developer mode, AllowDeveloperUnlock CSP, dynamic code dev gate, Option 19 interaction',
  },

  // ── File Rule Levels Reference (indices 30–41) ───────────────
  {
    file:  'docs/file-rule-levels/Level-Hash.md',
    label: 'Hash Rule Level',
    num:   'frl-hash',
    category: 'file-rule-level',
    tags:  ['Hash','AuthentiHash','SHA256','Most Specific'],
    desc:  'Most specific rule level: individually computed Authenticode/PE image hash for each binary. Requires policy update on any binary change including minor version bumps. Primary fallback for unsigned files.',
    keywords: 'Hash rule level, AuthentiHash, SHA256 hash, WDAC hash rule, PE image hash, unsigned file policy',
  },
  {
    file:  'docs/file-rule-levels/Level-FileName.md',
    label: 'FileName Rule Level',
    num:   'frl-filename',
    category: 'file-rule-level',
    tags:  ['FileName','OriginalFileName','VERSIONINFO'],
    desc:  'Trusts files based on OriginalFileName from PE VERSIONINFO resource header. No publisher check — any file with the matching name passes. Configurable via -SpecificFileNameLevel (ProductName, InternalName, etc.).',
    keywords: 'FileName rule level, OriginalFileName, VERSIONINFO, -SpecificFileNameLevel, ProductName, WDAC file name',
  },
  {
    file:  'docs/file-rule-levels/Level-FilePath.md',
    label: 'FilePath Rule Level',
    num:   'frl-filepath',
    category: 'file-rule-level',
    tags:  ['FilePath','User Mode Only','Windows 10 1903+','Option 18'],
    desc:  'Windows 10 1903+ user-mode only: allows binaries from specific filesystem paths. Wildcards supported. Vulnerable to symlink/junction attacks unless Option 18 (Disable Runtime FilePath Rule Protection) is NOT set.',
    keywords: 'FilePath rule level, path-based trust, WDAC FilePath, symlink attack, Option 18, admin-writable path, UNC path',
  },
  {
    file:  'docs/file-rule-levels/Level-SignedVersion.md',
    label: 'SignedVersion Rule Level',
    num:   'frl-signedversion',
    category: 'file-rule-level',
    tags:  ['SignedVersion','MinimumFileVersion','Publisher + Version'],
    desc:  'Combines Publisher (PCA cert + leaf CN) with a minimum version floor. Any signed file from the specified publisher at or above the minimum version passes — no filename binding.',
    keywords: 'SignedVersion rule level, MinimumFileVersion, WDAC version floor, publisher version, signed version rule',
  },
  {
    file:  'docs/file-rule-levels/Level-Publisher.md',
    label: 'Publisher Rule Level',
    num:   'frl-publisher',
    category: 'file-rule-level',
    tags:  ['Publisher','PCA Certificate','Leaf CN','Certificate'],
    desc:  'Combines the PCA certificate (typically one below root) with the CN of the leaf signing certificate. Trusts all files from a specific publisher — any version, any filename. Common for OEM driver suites.',
    keywords: 'Publisher rule level, PCA certificate, leaf CN, WDAC publisher trust, code signing publisher, intermediate cert',
  },
  {
    file:  'docs/file-rule-levels/Level-FilePublisher.md',
    label: 'FilePublisher Rule Level',
    num:   'frl-filepublisher',
    category: 'file-rule-level',
    tags:  ['FilePublisher','Most Used','FileName + Publisher + Version'],
    desc:  'Most widely used production rule level: triple binding of OriginalFileName + Publisher (PCA cert + leaf CN) + MinimumFileVersion. Survives app version updates; breaks only if publisher cert changes.',
    keywords: 'FilePublisher rule level, FileAttrib, WDAC FilePublisher, OriginalFileName publisher version, triple binding, -SpecificFileNameLevel',
  },
  {
    file:  'docs/file-rule-levels/Level-LeafCertificate.md',
    label: 'LeafCertificate Rule Level',
    num:   'frl-leafcert',
    category: 'file-rule-level',
    tags:  ['LeafCertificate','End-Entity Cert','Short Validity'],
    desc:  'Trusts files at the individual leaf (end-entity) signing certificate level. More specific than Publisher; no CA scope. Leaf certs typically expire in 1-3 years — requires policy update on cert renewal.',
    keywords: 'LeafCertificate rule level, end-entity certificate, WDAC leaf cert, cert renewal policy update, vendor certificate',
  },
  {
    file:  'docs/file-rule-levels/Level-PcaCertificate.md',
    label: 'PcaCertificate Rule Level',
    num:   'frl-pcacert',
    category: 'file-rule-level',
    tags:  ['PcaCertificate','Intermediate CA','Broadest Cert Level'],
    desc:  'Trusts files based on the highest available certificate in the chain (typically one below root). No leaf CN filter. Broader than Publisher — trusts everything signed by that intermediate CA, including other vendors.',
    keywords: 'PcaCertificate rule level, intermediate CA certificate, WDAC PCA cert, broadest cert trust, DigiCert intermediate',
  },
  {
    file:  'docs/file-rule-levels/Level-RootCertificate.md',
    label: 'RootCertificate Rule Level',
    num:   'frl-rootcert',
    category: 'file-rule-level',
    tags:  ['RootCertificate','NOT SUPPORTED','Unsupported'],
    desc:  'NOT SUPPORTED in App Control for Business. Trusting a root certificate would allow everything signed by that CA and all intermediates beneath it — catastrophically broad trust surface. Use PcaCertificate instead.',
    keywords: 'RootCertificate rule level, not supported, WDAC root cert, root CA trust, unsupported rule level',
  },
  {
    file:  'docs/file-rule-levels/Level-WHQL.md',
    label: 'WHQL Rule Level',
    num:   'frl-whql',
    category: 'file-rule-level',
    tags:  ['WHQL','Kernel Mode','Hardware Lab','EKU'],
    desc:  'Trusts binaries submitted to Microsoft and signed by the Windows Hardware Quality Lab. Primarily for kernel drivers. Checks for WHQL EKU (OID 1.3.6.1.4.1.311.10.3.5). Does not prevent BYOVD alone.',
    keywords: 'WHQL rule level, Windows Hardware Quality Lab, kernel driver trust, WHQL EKU, BYOVD, hardware certification',
  },
  {
    file:  'docs/file-rule-levels/Level-WHQLPublisher.md',
    label: 'WHQLPublisher Rule Level',
    num:   'frl-whqlpublisher',
    category: 'file-rule-level',
    tags:  ['WHQLPublisher','WHQL + Vendor CN','Kernel Mode'],
    desc:  'Combines WHQL EKU check with the CN of the leaf certificate — trusts WHQL drivers from a specific hardware vendor only. More specific than WHQL alone. Use for OEM-specific kernel driver allowlisting.',
    keywords: 'WHQLPublisher rule level, WHQL vendor CN, kernel driver publisher, OEM driver trust, WHQL leaf certificate',
  },
  {
    file:  'docs/file-rule-levels/Level-WHQLFilePublisher.md',
    label: 'WHQLFilePublisher Rule Level',
    num:   'frl-whqlfilepublisher',
    category: 'file-rule-level',
    tags:  ['WHQLFilePublisher','Most Specific WHQL','Triple WHQL Binding'],
    desc:  'Most specific WHQL level: WHQL EKU + vendor leaf CN + OriginalFileName + MinimumFileVersion. Primary kernel driver allowlisting approach in production policies. Auto-passes driver updates with same filename and cert.',
    keywords: 'WHQLFilePublisher rule level, WHQL FilePublisher, kernel driver specific, triple WHQL binding, driver version floor',
  },

  // ── Notes & Tips Reference (index 42) ───────────────────────
  {
    file:  'docs/notes/Notes-Tips-AppControl.md',
    label: 'Notes & Tips — App Control',
    num:   'notes-tips',
    category: 'notes',
    tags:  ['Tips','Best Practices','Gotchas','Reference'],
    desc:  'Comprehensive reference covering supplemental policy considerations, deny rule XML anatomy, rule precedence, policy merging, allow-list architecture, Microsoft recommended block rules, certificate chains, double-signed files, unsafe practices, and advanced WDAC gotchas.',
    keywords: 'WDAC notes tips best practices, supplemental policy, deny rules, rule precedence, policy merging, allow-list, block rules, certificate chains, advanced WDAC',
  },
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

/* ── Dynamic SEO — update meta tags on every part switch ─────── */
function updateSEO(part) {
  const isOpt   = part.category === 'rule-option';
  const partUrl = isOpt ? `${BASE_URL}#${part.num}` : `${BASE_URL}#part${part.num}`;
  const title   = isOpt
    ? `${part.label} | WDAC Rule Options — Anubhav Gain`
    : `Part ${part.num}: ${part.label} | ${SITE_NAME} — Anubhav Gain`;
  const desc    = part.desc;

  // <title>
  document.title = title;

  // Canonical
  const canon = document.getElementById('canonical');
  if (canon) canon.href = partUrl;

  // Meta description
  setMeta('name', 'description', desc);
  setMeta('name', 'keywords',    part.keywords + ', App Control for Business, WDAC, Anubhav Gain');

  // Open Graph
  setMeta('property', 'og:title',       title,   'id', 'og-title');
  setMeta('property', 'og:description', desc,    'id', 'og-desc');
  setMeta('property', 'og:url',         partUrl, 'id', 'og-url');

  // Twitter
  setMeta('name', 'twitter:title',       title, 'id', 'tw-title');
  setMeta('name', 'twitter:description', desc,  'id', 'tw-desc');

  // Breadcrumb JSON-LD
  const ldBC = document.getElementById('ld-breadcrumb');
  if (ldBC) {
    ldBC.textContent = JSON.stringify({
      '@context': 'https://schema.org',
      '@type': 'BreadcrumbList',
      itemListElement: [
        { '@type': 'ListItem', position: 1, name: SITE_NAME, item: BASE_URL },
        { '@type': 'ListItem', position: 2,
          name: isOpt ? part.label : `Part ${part.num}: ${part.label}`,
          item: partUrl },
      ],
    });
  }

  // Update aria-current on sidebar items
  navItems.forEach((item, i) => {
    if (i === currentPart) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  });

  // Update sidebar-toggle aria-expanded
  const toggleBtn = document.getElementById('sidebar-toggle');
  if (toggleBtn) toggleBtn.setAttribute('aria-expanded', sidebar.classList.contains('open') ? 'true' : 'false');

  // Update progress-bar aria-valuenow
  document.getElementById('progress-bar')?.setAttribute('aria-valuenow', '0');

  // Push browser history state (enables back/forward between parts)
  history.pushState({ part: part.num }, title, isOpt ? `#${part.num}` : `#part${part.num}`);
}

/* Helper: find or create a <meta> and set its content */
function setMeta(attrKey, attrVal, content, idKey, idVal) {
  let el = idKey
    ? document.getElementById(idVal)
    : document.querySelector(`meta[${attrKey}="${attrVal}"]`);
  if (!el) {
    el = document.createElement('meta');
    el.setAttribute(attrKey, attrVal);
    if (idKey) el.id = idVal;
    document.head.appendChild(el);
  }
  el.setAttribute('content', content);
}

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

/* ── Mermaid diagram rendering ────────────────────────────────── */
async function renderMermaid(container) {
  if (typeof mermaid === 'undefined') return;

  // Find all mermaid code blocks (marked outputs <code class="language-mermaid">)
  const blocks = container.querySelectorAll('pre code.language-mermaid, code.language-mermaid');
  if (blocks.length === 0) return;

  blocks.forEach((block, i) => {
    const diagram = block.innerText || block.textContent;
    const pre = block.closest('pre') || block.parentElement;

    // Create mermaid container
    const wrap = document.createElement('div');
    wrap.className = 'mermaid-wrap';

    const mermaidDiv = document.createElement('div');
    mermaidDiv.className = 'mermaid';
    mermaidDiv.id = `mermaid-${Date.now()}-${i}`;
    mermaidDiv.textContent = diagram;

    wrap.appendChild(mermaidDiv);
    pre.parentNode.replaceChild(wrap, pre);
  });

  // Re-run mermaid on newly added diagrams
  try {
    await mermaid.run({ nodes: container.querySelectorAll('.mermaid') });
  } catch (e) {
    console.warn('Mermaid render error:', e);
  }
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
  const isOpt = part.category === 'rule-option';
  const isFrlCard  = part.category === 'file-rule-level';
  const isNoteCard = part.category === 'notes';
  const numDisplay = isOpt
    ? part.num.replace('opt-', '').replace('dev', 'Dev').toUpperCase()
    : isFrlCard ? part.num.replace('frl-', '').toUpperCase()
    : isNoteCard ? 'NT'
    : String(part.num).padStart(2, '0');
  const seriesLabel = isOpt ? 'WDAC Policy Rule Options — Reference'
    : isFrlCard ? 'WDAC File Rule Levels — Reference'
    : isNoteCard ? 'App Control — Notes & Tips'
    : 'Mastering App Control for Business';
  const cardClass = isOpt ? ' phc-opt' : isFrlCard ? ' phc-frl' : isNoteCard ? ' phc-opt' : '';
  return `
<div class="part-header-card${cardClass}">
  <div class="phc-num">${numDisplay}</div>
  <div class="phc-meta">
    <div class="phc-label">${seriesLabel}</div>
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

/* ── Dots — only for main parts (not rule options) ────────────── */
const dotPartMap = []; // maps dot-index → PARTS-index

function buildDots() {
  partDots.innerHTML = '';
  dotPartMap.length  = 0;
  PARTS.forEach((p, i) => {
    if (p.category === 'rule-option') return;
    dotPartMap.push(i);
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
  partDots.querySelectorAll('.dot').forEach((d, di) => {
    d.classList.toggle('active', dotPartMap[di] === currentPart);
  });
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
  updateSEO(part);
  const isOpt2 = part.category === 'rule-option';
  const isFrl  = part.category === 'file-rule-level';
  const isNote = part.category === 'notes';
  bcPart.textContent = isOpt2
    ? `Option ${part.num.replace('opt-', '').replace('dev', 'Dev').toUpperCase()}`
    : isFrl ? `Level: ${part.num.replace('frl-', '').toUpperCase()}`
    : isNote ? 'Notes & Tips'
    : `Part ${part.num}`;
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
    await renderMermaid(content);
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
  // Update mermaid theme and re-render current diagrams
  if (typeof mermaid !== 'undefined') {
    mermaid.initialize({
      startOnLoad: false,
      theme: next === 'light' ? 'default' : 'dark',
      securityLevel: 'loose',
      fontFamily: 'Inter, system-ui, sans-serif',
    });
    renderMermaid(content);
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

/* ── Browser back / forward support ──────────────────────────── */
window.addEventListener('popstate', e => {
  const partNum = e.state?.part;
  if (partNum) {
    const idx = PARTS.findIndex(p => p.num === partNum);
    if (idx >= 0) loadPart(idx);
  }
});

/* ── Init ─────────────────────────────────────────────────────── */
(function init() {
  // Restore theme
  const theme = localStorage.getItem('acfb-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', theme);
  themeBtn.textContent = theme === 'light' ? '☀' : '☾';
  if (theme === 'light') {
    const hljsLink = document.getElementById('hljs-theme');
    if (hljsLink) hljsLink.href = 'https://cdn.jsdelivr.net/npm/highlight.js@11.9.0/styles/github.min.css';
  }

  // Initialize Mermaid
  if (typeof mermaid !== 'undefined') {
    mermaid.initialize({
      startOnLoad: false,
      theme: localStorage.getItem('acfb-theme') === 'light' ? 'default' : 'dark',
      securityLevel: 'loose',
      fontFamily: 'Inter, system-ui, sans-serif',
      flowchart: { curve: 'basis', padding: 20 },
      sequence: { actorMargin: 60, messageMargin: 40 },
    });
  }

  buildDots();

  // Deep-link: load part from URL hash (#part3 for main parts, #opt-13 for rule options)
  const hash      = window.location.hash;
  const partMatch = hash.match(/#part(\d+)/);
  const optMatch  = hash.match(/#(opt-[\w]+)/);
  let startIdx    = 0;
  if (partMatch) {
    startIdx = Math.max(0, Math.min(PARTS.length - 1, parseInt(partMatch[1]) - 1));
  } else if (optMatch) {
    const found = PARTS.findIndex(p => p.num === optMatch[1]);
    if (found >= 0) startIdx = found;
  }

  loadPart(startIdx);
})();

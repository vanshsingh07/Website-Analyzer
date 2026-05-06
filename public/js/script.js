/**
 * ============================================================
 *  SiteShield — script.js
 *  All frontend logic: API calls, UI rendering, tab switching,
 *  modal, loading animation, score visualisations.
 * ============================================================
 */

// ── State ────────────────────────────────────────────────────
let currentReport = null;

// ── Helpers ──────────────────────────────────────────────────
const $  = id => document.getElementById(id);
const set = (id, html) => { const el = $(id); if (el) el.innerHTML = html; };
const txt = (id, val) => { const el = $(id); if (el) el.textContent = val || '—'; };

function quickFill(val) {
  $('targetInput').value = val;
  $('targetInput').focus();
}

// ── Loading animation ─────────────────────────────────────────
const loadingMessages = [
  'Resolving DNS records…',
  'Probing IP geolocation…',
  'Fetching TLS certificate…',
  'Scraping website metadata…',
  'Fingerprinting technologies…',
  'Calculating risk score…',
  'Building trust profile…',
  'Assembling report…'
];

function startLoadingAnimation() {
  let step = 0;
  const bar  = $('loadingBarFill');
  const stat = $('loadingStatus');
  const total = loadingMessages.length;

  const interval = setInterval(() => {
    if (step >= total) { clearInterval(interval); return; }
    stat.textContent = loadingMessages[step];
    bar.style.width  = `${((step + 1) / total) * 95}%`;
    step++;
  }, 900);

  return interval;
}

// ── Main entry point ─────────────────────────────────────────
async function startAnalysis() {
  const target = $('targetInput').value.trim();
  if (!target) {
    $('targetInput').style.outline = '2px solid rgba(255,61,90,.6)';
    setTimeout(() => $('targetInput').style.outline = '', 1500);
    return;
  }

  // Show loading, hide hero & dashboard
  $('hero').style.display      = 'none';
  $('dashboard').style.display = 'none';
  $('loadingScreen').style.display = 'flex';

  const timer = startLoadingAnimation();

  try {
    const res  = await fetch('/api/analyze', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ target })
    });

    const data = await res.json();
    clearInterval(timer);

    if (!data.success) throw new Error(data.error || 'Analysis failed.');

    currentReport = data.report;
    renderDashboard(data.report);

    $('loadingScreen').style.display = 'none';
    $('dashboard').style.display     = 'block';
    switchTab('basic');

  } catch (err) {
    clearInterval(timer);
    $('loadingScreen').style.display = 'none';
    $('hero').style.display          = '';
    alert('Error: ' + err.message);
  }
}

// Enter key support
document.addEventListener('DOMContentLoaded', () => {
  $('targetInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') startAnalysis();
  });
});

// ── Reset ────────────────────────────────────────────────────
function resetApp() {
  $('dashboard').style.display = 'none';
  $('hero').style.display      = '';
  currentReport = null;
}

// ── Tab switching ─────────────────────────────────────────────
function switchTab(name) {
  document.querySelectorAll('.tab-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === name);
  });
  document.querySelectorAll('.tab-pane').forEach(p => {
    p.classList.toggle('active', p.id === `tab-${name}`);
  });
}

// ════════════════════════════════════════════════════════════
//  RENDER DASHBOARD
// ════════════════════════════════════════════════════════════
function renderDashboard(r) {
  // Header
  $('dashTarget').textContent = r.meta.hostname;
  $('dashMeta').textContent   = `Analyzed at ${new Date(r.meta.analyzedAt).toLocaleString()}`;

  renderBasicInfo(r);
  renderIPIntel(r);
  renderRisk(r);
  renderSSL(r);
  renderTrust(r);
}

// ── Basic Info ────────────────────────────────────────────────
function renderBasicInfo(r) {
  const b = r.basicInfo;
  txt('bi-domain',   b.domain);
  txt('bi-ip',       b.ip);
  txt('bi-country',  b.country);
  txt('bi-city',     `${b.city}, ${b.region}`);
  txt('bi-isp',      b.isp);
  txt('bi-org',      `${b.org} · ${b.asn}`);

  const w = r.websiteInfo;
  txt('bi-title',    w.title);
  txt('bi-desc',     w.description);
  set('bi-sitetype', `<span class="badge-type">${w.siteType}</span>`);

  // Tech tags
  const techColors = {
    'WordPress':       ['#21759b','rgba(33,117,155,.15)'],
    'React':           ['#61dafb','rgba(97,218,251,.1)'],
    'Vue.js':          ['#42b883','rgba(66,184,131,.1)'],
    'Angular':         ['#dd1b16','rgba(221,27,22,.1)'],
    'Next.js':         ['#ffffff','rgba(255,255,255,.07)'],
    'Nuxt.js':         ['#00c58e','rgba(0,197,142,.1)'],
    'Bootstrap':       ['#7952b3','rgba(121,82,179,.1)'],
    'Tailwind CSS':    ['#38bdf8','rgba(56,189,248,.1)'],
    'jQuery':          ['#0769ad','rgba(7,105,173,.1)'],
    'Shopify':         ['#96bf48','rgba(150,191,72,.1)'],
    'PHP':             ['#8892be','rgba(136,146,190,.1)'],
    'Node.js':         ['#68a063','rgba(104,160,99,.1)'],
    'Nginx':           ['#009900','rgba(0,153,0,.1)'],
    'Apache':          ['#d22128','rgba(210,33,40,.1)'],
    'Cloudflare':      ['#f38020','rgba(243,128,32,.1)'],
    'Google Analytics':['#e8710a','rgba(232,113,10,.1)'],
  };

  const wrap = $('techTags');
  if (!w.technologies.length) {
    wrap.innerHTML = '<span style="color:var(--text-dim);font-size:13px;font-family:var(--font-mono)">No technologies detected</span>';
    return;
  }
  wrap.innerHTML = w.technologies.map(t => {
    const [color, bg] = techColors[t] || ['#7a88aa','rgba(122,136,170,.1)'];
    return `<span class="tech-tag" style="background:${bg};border-color:${color}40;color:${color}">${t}</span>`;
  }).join('');
}

// ── IP Intelligence ───────────────────────────────────────────
function renderIPIntel(r) {
  const ip = r.ipIntelligence;
  txt('ii-type',    ip.ipType);
  txt('ii-network', ip.networkType);
  txt('ii-hosting', ip.isHosting ? '⚠ Yes — cloud / data centre' : '✓ No — residential / business');
  txt('ii-proxy',   ip.isProxy   ? '⚠ Yes — VPN or proxy detected' : '✓ No proxy detected');
  txt('ii-geo',     `${r.basicInfo.city}, ${r.basicInfo.country}`);
  txt('ii-asn',     r.basicInfo.asn);

  // Flags
  const flags = [];
  flags.push({ label: ip.isProxy   ? '⚠ VPN / Proxy Detected'  : '✓ Clean IP — No Proxy',   cls: ip.isProxy   ? 'flag-warn'   : 'flag-safe' });
  flags.push({ label: ip.isHosting ? '⚠ Hosted on Cloud Server' : '✓ Residential / Business', cls: ip.isHosting ? 'flag-warn'   : 'flag-safe' });
  flags.push({ label: ip.ipType === 'Public' ? '✓ Publicly Reachable'  : '⚠ Private / Internal IP',  cls: ip.ipType === 'Public' ? 'flag-safe' : 'flag-danger' });

  $('intelFlags').innerHTML = flags.map(f =>
    `<div class="intel-flag ${f.cls}">${f.label}</div>`
  ).join('');
}

// ── Risk Analysis ─────────────────────────────────────────────
function renderRisk(r) {
  const ra = r.riskAnalysis;
  const score = ra.riskScore;

  // Gauge
  const arc = 283; // full arc length (approx half-circle)
  const filled = (score / 100) * arc;
  $('gaugeFill').style.strokeDasharray = `${filled} ${arc}`;

  // Colour by level
  const colours = { LOW: '#00ff9d', MEDIUM: '#ffdb3d', HIGH: '#ff3d5a' };
  const colour  = colours[ra.riskLevel] || '#00e5ff';
  $('gaugeFill').style.stroke = colour;

  txt('gaugeScore', score);

  const badge = $('riskBadge');
  badge.textContent = ra.riskLevel;
  badge.className   = `risk-badge badge-${ra.riskLevel}`;

  // Summary text
  const summaries = {
    LOW:    'This target appears relatively safe. Standard precautions apply.',
    MEDIUM: 'Some risk indicators were found. Review the factors carefully.',
    HIGH:   'Multiple red flags detected. Exercise extreme caution.'
  };
  set('riskSummary', `<span style="color:${colour}">${ra.riskLevel} RISK</span><br/><span style="font-size:16px;font-weight:400;color:var(--text-secondary)">${summaries[ra.riskLevel]}</span>`);

  // Reasons
  if (!ra.reasons.length) {
    $('riskReasons').innerHTML = '<div class="no-reasons">✓ No significant risk factors detected.</div>';
  } else {
    const bullets = { LOW: '🟢', MEDIUM: '🟡', HIGH: '🔴' };
    $('riskReasons').innerHTML = ra.reasons.map(r =>
      `<div class="risk-reason"><span class="reason-bullet">${bullets[ra.riskLevel]}</span>${r}</div>`
    ).join('');
  }
}

// ── SSL ───────────────────────────────────────────────────────
function renderSSL(r) {
  const ssl = r.ssl;

  if (!ssl.enabled) {
    $('sslStatusCard').style.borderColor = 'rgba(255,61,90,.3)';
    set('sslIcon',       '🔓');
    set('sslStatusText', '<span style="color:var(--red)">No SSL / TLS</span>');
    txt('sslStatusSub',  'This site does not use HTTPS. Data is sent unencrypted.');
    $('sslDetails').style.display = 'none';
    return;
  }

  const isValid = ssl.isValid;
  $('sslStatusCard').style.borderColor = isValid ? 'rgba(0,255,157,.25)' : 'rgba(255,219,61,.3)';
  set('sslIcon',       isValid ? '🔒' : '⚠️');
  set('sslStatusText', isValid
    ? '<span style="color:var(--green)">SSL Certificate Valid</span>'
    : '<span style="color:var(--yellow)">SSL Certificate Issue</span>');
  txt('sslStatusSub', ssl.selfSigned
    ? 'Self-signed certificate — not trusted by browsers.'
    : `Expires in ${ssl.daysLeft} day${ssl.daysLeft !== 1 ? 's' : ''}`);

  $('sslDetails').style.display = '';
  txt('ssl-subject', ssl.subject);
  txt('ssl-issuer',  ssl.issuer);
  txt('ssl-from',    ssl.validFrom);
  txt('ssl-to',      ssl.validTo);

  const daysEl = $('ssl-days');
  daysEl.textContent = ssl.daysLeft;
  daysEl.style.color = ssl.daysLeft > 60 ? 'var(--green)' : ssl.daysLeft > 14 ? 'var(--yellow)' : 'var(--red)';

  txt('ssl-self', ssl.selfSigned ? '⚠ Yes' : '✓ No');
}

// ── Trust Score ────────────────────────────────────────────────
function renderTrust(r) {
  const ts    = r.trustScore.score;
  const circ  = 408; // full circumference (2π×65)
  const fill  = (ts / 100) * circ;

  const circle = $('trustCircle');
  circle.style.strokeDasharray = `${fill} ${circ}`;

  const colour = ts >= 70 ? 'var(--green)' : ts >= 45 ? 'var(--yellow)' : 'var(--red)';
  circle.style.stroke = colour;
  txt('trustScore', ts);

  // Stars (out of 5)
  const stars = Math.round((ts / 100) * 5);
  $('trustStars').innerHTML = Array.from({ length: 5 }, (_, i) =>
    `<span style="color:${i < stars ? '#ffdb3d' : 'rgba(255,255,255,.12)'}">${i < stars ? '★' : '☆'}</span>`
  ).join('');

  const verdicts = [
    [80, '✓ Highly Trustworthy'],
    [60, '~ Mostly Trustworthy'],
    [40, '⚠ Use With Caution'],
    [0,  '✗ Untrusted / Risky']
  ];
  const verdict = verdicts.find(([min]) => ts >= min);
  set('trustVerdict', `<span style="color:${colour}">${verdict[1]}</span>`);

  // Factors
  const factors = r.trustScore.factors;
  const rows = [
    { label: 'SSL Certificate Present',   pass: factors.sslExists },
    { label: 'SSL Certificate Valid',     pass: factors.sslValid },
    { label: 'No VPN / Proxy Detected',   pass: factors.noProxy },
    { label: 'Page Metadata Present',     pass: factors.hasMetadata },
    { label: 'Protected by Cloudflare',   pass: factors.cfProtected },
  ];
  $('trustFactors').innerHTML = rows.map(f => `
    <div class="trust-factor">
      <span class="tf-label">${f.label}</span>
      <span class="tf-val ${f.pass ? 'tf-pass' : 'tf-fail'}">${f.pass ? '✓ PASS' : '✗ FAIL'}</span>
    </div>
  `).join('');
}

// ════════════════════════════════════════════════════════════
//  MODAL — AI Intelligence Report
//  (Generates explanation dynamically from report data)
// ════════════════════════════════════════════════════════════
function openModal() {
  if (!currentReport) return;
  const overlay = $('modalOverlay');
  overlay.classList.add('open');
  $('modalSub').textContent  = currentReport.meta.hostname;
  $('modalBody').innerHTML   = '<div class="modal-loader"><div class="ml-dot"></div><div class="ml-dot"></div><div class="ml-dot"></div></div>';

  // Simulate a brief "thinking" delay then render
  setTimeout(() => renderModalContent(currentReport), 1400);
}

function closeModal(e) {
  if (e.target === $('modalOverlay')) closeModalDirect();
}
function closeModalDirect() {
  $('modalOverlay').classList.remove('open');
}

function renderModalContent(r) {
  const w   = r.websiteInfo;
  const b   = r.basicInfo;
  const ra  = r.riskAnalysis;
  const ts  = r.trustScore.score;
  const ssl = r.ssl;

  // Determine purpose / activity description
  const typeDescriptions = {
    'E-Commerce Store':         'This appears to be an online retail or shopping platform. It likely sells products or services directly to consumers.',
    'Blog / CMS':               'This site is a content-driven blog or news publication, regularly publishing articles, posts, or editorial content.',
    'WordPress Website':        'Built on WordPress — one of the most popular CMS platforms. Could serve any purpose from blogs to business sites.',
    'AI / Tech Product':        'This appears to be a technology or AI-focused product or service. It likely offers software tools, APIs, or machine learning capabilities.',
    'News / Media':             'A news or media outlet that publishes reporting, journalism, or editorial content.',
    'Portfolio / Personal':     'A personal or portfolio website, likely belonging to an individual or freelancer showcasing their work.',
    'Developer Documentation':  'This is a technical documentation site, intended for developers integrating with an API or library.',
    'SaaS / Web Application':   'A Software-as-a-Service (SaaS) platform. Users likely log in to access a web-based application or dashboard.',
    'Educational Institution':  'An academic or educational platform, possibly a university, school, or online learning service.',
    'Financial Services':       'A financial services site — this could be a bank, investment platform, or fintech application. Verify legitimacy carefully.',
    'Healthcare / Medical':     'A healthcare or medical information site. Always verify with registered medical professionals.',
    'Modern Web Application':   'A modern single-page application (SPA) built with current JavaScript frameworks.',
    'General Website':          'A general-purpose website. The specific intent is unclear without deeper content review.'
  };

  const typeDesc = typeDescriptions[w.siteType] || typeDescriptions['General Website'];

  // Build risk narrative
  let riskNarrative = '';
  if (ra.riskLevel === 'LOW')    riskNarrative = 'The risk profile for this target is <strong style="color:var(--green)">LOW</strong>. No major red flags were detected during automated scanning. Standard internet safety practices still apply.';
  if (ra.riskLevel === 'MEDIUM') riskNarrative = 'The risk profile for this target is <strong style="color:var(--yellow)">MEDIUM</strong>. Some concerns were identified — review the Risk Analysis tab for specifics before fully trusting this site.';
  if (ra.riskLevel === 'HIGH')   riskNarrative = 'The risk profile for this target is <strong style="color:var(--red)">HIGH</strong>. Multiple indicators of risk were detected. Proceed with extreme caution or avoid sharing sensitive information.';

  // Build tech summary
  const techSummary = w.technologies.length
    ? `The site uses: <strong>${w.technologies.join(', ')}</strong>.`
    : 'No specific technologies were fingerprinted on this site.';

  // Build SSL narrative
  const sslNarrative = ssl.enabled && ssl.isValid
    ? `The site has a <strong style="color:var(--green)">valid SSL certificate</strong> issued by ${ssl.issuer}, expiring in ${ssl.daysLeft} days. Data is transmitted securely.`
    : ssl.enabled
      ? `An SSL certificate exists but has issues (${ssl.selfSigned ? 'self-signed' : 'expired/invalid'}). Exercise caution with sensitive data.`
      : `<strong style="color:var(--red)">No SSL certificate was found.</strong> All data sent to this site is transmitted in plain text.`;

  // Trust narrative
  let trustNarrative = '';
  if (ts >= 80)      trustNarrative = `With a trust score of <strong style="color:var(--green)">${ts}/100</strong>, this site ranks as highly trustworthy. Multiple positive signals were detected.`;
  else if (ts >= 55) trustNarrative = `With a trust score of <strong style="color:var(--yellow)">${ts}/100</strong>, this site is moderately trustworthy. Some factors reduced confidence.`;
  else               trustNarrative = `With a trust score of <strong style="color:var(--red)">${ts}/100</strong>, this site has a low trust rating. Several trust factors failed.`;

  $('modalBody').innerHTML = `
    <div class="modal-section">
      <div class="modal-section-title">What is this site?</div>
      <p><strong>${w.title || b.domain}</strong> — ${typeDesc}</p>
      ${w.description ? `<p style="margin-top:10px;color:var(--text-secondary);font-style:italic">"${w.description}"</p>` : ''}
    </div>

    <div class="modal-section">
      <div class="modal-section-title">Site Classification</div>
      <p>Classified as: <strong>${w.siteType}</strong></p>
      <p style="margin-top:8px">${techSummary}</p>
    </div>

    <div class="modal-section">
      <div class="modal-section-title">Security Assessment</div>
      <p>${riskNarrative}</p>
      <p style="margin-top:10px">${sslNarrative}</p>
    </div>

    <div class="modal-section">
      <div class="modal-section-title">Trust Profile</div>
      <p>${trustNarrative}</p>
    </div>

    <div class="modal-section">
      <div class="modal-section-title">Network Intelligence</div>
      <p>Hosted in <strong>${b.city}, ${b.country}</strong> via <strong>${b.isp}</strong>.</p>
      <p style="margin-top:8px">
        IP type: <strong>${r.ipIntelligence.ipType}</strong> ·
        Network: <strong>${r.ipIntelligence.networkType}</strong> ·
        ${r.ipIntelligence.isProxy ? '<strong style="color:var(--red)">VPN/Proxy detected</strong>' : '<strong style="color:var(--green)">No proxy detected</strong>'}
      </p>
    </div>

    <div class="modal-section" style="background:rgba(155,92,255,.06);border:1px solid rgba(155,92,255,.15);border-radius:12px;padding:16px">
      <div class="modal-section-title" style="color:var(--purple)">Analyst Note</div>
      <p style="font-size:12px">This report is generated automatically from public data sources. It is informational only and should not be used as the sole basis for security decisions. For sensitive use-cases, pair with manual investigation.</p>
    </div>
  `;
}

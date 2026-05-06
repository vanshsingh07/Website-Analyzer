/**
 * ============================================================
 *  Website Intelligence & Security Analyzer — server.js
 *  Backend: Node.js + Express
 *  All analysis logic lives here; frontend calls these APIs.
 * ============================================================
 */

const express  = require('express');
const axios    = require('axios');
const cheerio  = require('cheerio');
const dns      = require('dns').promises;
const https    = require('https');
const tls      = require('tls');
const path     = require('path');
const cors     = require('cors');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Helpers ───────────────────────────────────────────────────

/**
 * Clean a user-supplied target into a plain hostname/IP.
 * Strips protocol, www, trailing slashes, and paths.
 */
function cleanHost(raw) {
  let s = raw.trim().toLowerCase();
  s = s.replace(/^https?:\/\//, '');
  s = s.replace(/^www\./, '');
  s = s.split('/')[0].split('?')[0].split('#')[0];
  return s;
}

/** Return true if the string looks like an IPv4 address. */
function isIP(str) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(str);
}

/** Resolve a hostname → first IPv4 address. */
async function resolveIP(hostname) {
  try {
    const addrs = await dns.resolve4(hostname);
    return addrs[0] || null;
  } catch {
    return null;
  }
}

/** Classify an IP as private/loopback or public. */
function ipType(ip) {
  if (!ip) return 'Unknown';
  const parts = ip.split('.').map(Number);
  if (parts[0] === 10) return 'Private';
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return 'Private';
  if (parts[0] === 192 && parts[1] === 168) return 'Private';
  if (parts[0] === 127) return 'Loopback';
  return 'Public';
}

/**
 * Fetch geo + ISP data from ip-api.com (free, no key needed).
 * Returns a normalised object.
 */
async function fetchIPInfo(ip) {
  try {
    const { data } = await axios.get(
      `http://ip-api.com/json/${ip}?fields=status,country,countryCode,regionName,city,zip,lat,lon,isp,org,as,hosting,proxy,query`,
      { timeout: 8000 }
    );
    if (data.status === 'success') return data;
  } catch {}
  return null;
}

/**
 * Scrape the target URL for <title>, <meta description>,
 * and technology fingerprints.
 */
async function scrapeWebsite(hostname) {
  const result = {
    title: null,
    description: null,
    technologies: [],
    hasSSL: false,
    headers: {}
  };

  for (const proto of ['https', 'http']) {
    try {
      const url = `${proto}://${hostname}`;
      const { data: html, headers } = await axios.get(url, {
        timeout: 10000,
        maxRedirects: 5,
        headers: {
          'User-Agent':
            'Mozilla/5.0 (compatible; SiteAnalyzerBot/1.0)'
        },
        // Accept self-signed certs so we can still scrape
        httpsAgent: new (require('https').Agent)({
          rejectUnauthorized: false
        })
      });

      result.hasSSL    = proto === 'https';
      result.headers   = headers;

      const $ = cheerio.load(html);
      result.title       = $('title').first().text().trim() || null;
      result.description =
        $('meta[name="description"]').attr('content')?.trim() ||
        $('meta[property="og:description"]').attr('content')?.trim() ||
        null;

      // ── Technology fingerprinting ─────────────────────────
      const htmlLower  = html.toLowerCase();
      const powered    = (headers['x-powered-by'] || '').toLowerCase();
      const server     = (headers['server']       || '').toLowerCase();

      const techChecks = [
        { name: 'WordPress',   test: () => htmlLower.includes('wp-content') || htmlLower.includes('wp-includes') },
        { name: 'React',       test: () => htmlLower.includes('react') || htmlLower.includes('__react') || htmlLower.includes('_reactfiber') },
        { name: 'Vue.js',      test: () => htmlLower.includes('vue.js') || htmlLower.includes('__vue') },
        { name: 'Angular',     test: () => htmlLower.includes('ng-version') || htmlLower.includes('angular') },
        { name: 'Next.js',     test: () => htmlLower.includes('__next') || htmlLower.includes('_next/') },
        { name: 'Nuxt.js',     test: () => htmlLower.includes('__nuxt') || htmlLower.includes('_nuxt/') },
        { name: 'Bootstrap',   test: () => htmlLower.includes('bootstrap') },
        { name: 'Tailwind CSS',test: () => htmlLower.includes('tailwind') },
        { name: 'jQuery',      test: () => htmlLower.includes('jquery') },
        { name: 'Shopify',     test: () => htmlLower.includes('shopify') },
        { name: 'Wix',         test: () => htmlLower.includes('wix.com') },
        { name: 'Squarespace', test: () => htmlLower.includes('squarespace') },
        { name: 'PHP',         test: () => powered.includes('php') || (headers['set-cookie'] || '').includes('PHPSESSID') },
        { name: 'Node.js',     test: () => powered.includes('node') || powered.includes('express') },
        { name: 'Nginx',       test: () => server.includes('nginx') },
        { name: 'Apache',      test: () => server.includes('apache') },
        { name: 'Cloudflare',  test: () => server.includes('cloudflare') || !!headers['cf-ray'] },
        { name: 'Google Analytics', test: () => htmlLower.includes('google-analytics') || htmlLower.includes('gtag') },
      ];

      result.technologies = techChecks
        .filter(t => t.test())
        .map(t => t.name);

      break; // stop after first successful fetch
    } catch {}
  }

  return result;
}

/**
 * Retrieve TLS/SSL certificate details for a hostname.
 */
function getSSLInfo(hostname) {
  return new Promise(resolve => {
    try {
      const socket = tls.connect(
        443,
        hostname,
        { rejectUnauthorized: false, servername: hostname },
        () => {
          const cert = socket.getPeerCertificate(true);
          socket.destroy();
          if (!cert || !cert.subject) return resolve(null);

          const validFrom = new Date(cert.valid_from);
          const validTo   = new Date(cert.valid_to);
          const now       = new Date();
          const daysLeft  = Math.ceil((validTo - now) / 86400000);

          resolve({
            subject:   cert.subject?.CN || hostname,
            issuer:    cert.issuer?.O  || cert.issuer?.CN || 'Unknown',
            validFrom: validFrom.toDateString(),
            validTo:   validTo.toDateString(),
            daysLeft,
            isValid:   now >= validFrom && now <= validTo,
            selfSigned: cert.issuer?.CN === cert.subject?.CN
          });
        }
      );
      socket.setTimeout(8000, () => { socket.destroy(); resolve(null); });
      socket.on('error', () => resolve(null));
    } catch {
      resolve(null);
    }
  });
}

/**
 * Core scoring engine.
 * Returns riskScore (0–100, higher = riskier) and
 * trustScore (0–100, higher = more trustworthy).
 */
function calculateScores({ ipInfo, ssl, scrape, ip }) {
  const reasons   = [];
  let   riskScore = 0;

  // ── Risk factors ─────────────────────────────────────────
  if (ipInfo?.proxy)   { riskScore += 30; reasons.push('Traffic routed through a proxy or VPN — common in anonymisation tools and malicious actors.'); }
  if (ipInfo?.hosting) { riskScore += 15; reasons.push('Hosted on a cloud/hosting provider — legitimate for businesses but also common for phishing & bots.'); }
  if (!ssl)            { riskScore += 20; reasons.push('No SSL/TLS certificate found — data transmitted in plain text, high interception risk.'); }
  else if (ssl && !ssl.isValid) { riskScore += 20; reasons.push('SSL certificate is expired or invalid — browser warnings will appear.'); }
  else if (ssl?.selfSigned)     { riskScore += 10; reasons.push('Self-signed certificate — not trusted by browsers by default.'); }
  else if (ssl && ssl.daysLeft < 30) { riskScore += 10; reasons.push(`SSL certificate expires in ${ssl.daysLeft} days — renewal overdue.`); }

  if (!scrape.title && !scrape.description) {
    riskScore += 10;
    reasons.push('No page title or meta description found — may indicate a hidden or under-construction site.');
  }

  const riskyTech = ['WordPress'];
  const found = riskyTech.filter(t => scrape.technologies.includes(t));
  if (found.length) {
    riskScore += 5;
    reasons.push(`Uses ${found.join(', ')} — popular CMS platforms are frequent attack targets when unpatched.`);
  }

  if (ipType(ip) === 'Private') {
    riskScore += 5;
    reasons.push('Target resolves to a private/internal IP — not publicly reachable from the internet.');
  }

  riskScore = Math.min(100, riskScore);

  // ── Risk label ────────────────────────────────────────────
  let riskLevel;
  if (riskScore <= 25)      riskLevel = 'LOW';
  else if (riskScore <= 55) riskLevel = 'MEDIUM';
  else                      riskLevel = 'HIGH';

  // ── Trust score (inverse of risk, weighted) ───────────────
  let trust = 100;
  if (!ssl)                               trust -= 25;
  else if (ssl && !ssl.isValid)           trust -= 20;
  else if (ssl && ssl.daysLeft < 30)      trust -= 10;
  if (ipInfo?.proxy)                      trust -= 20;
  if (!scrape.title)                      trust -= 10;
  if (ipInfo?.hosting && ipInfo?.proxy)   trust -= 10;
  if (scrape.hasSSL && ssl?.isValid)      trust += 10;
  if (scrape.technologies.includes('Cloudflare')) trust += 5;

  trust = Math.max(0, Math.min(100, trust));

  return { riskScore, riskLevel, trustScore: trust, reasons };
}

/**
 * Derive a human-readable site-type label from scraped metadata
 * and detected technologies.
 */
function classifySiteType({ technologies, title, description }) {
  const all = `${title || ''} ${description || ''}`.toLowerCase();

  if (technologies.includes('Shopify') || all.includes('shop') || all.includes('cart') || all.includes('buy')) return 'E-Commerce Store';
  if (technologies.includes('WordPress') && (all.includes('blog') || all.includes('post'))) return 'Blog / CMS';
  if (technologies.includes('WordPress')) return 'WordPress Website';
  if (all.includes('ai') || all.includes('machine learning') || all.includes('artificial intelligence')) return 'AI / Tech Product';
  if (all.includes('news') || all.includes('article') || all.includes('journalist')) return 'News / Media';
  if (all.includes('portfolio') || all.includes('freelance') || all.includes('designer')) return 'Portfolio / Personal';
  if (all.includes('docs') || all.includes('documentation') || all.includes('api reference')) return 'Developer Documentation';
  if (all.includes('login') || all.includes('dashboard') || all.includes('saas')) return 'SaaS / Web Application';
  if (all.includes('university') || all.includes('school') || all.includes('education')) return 'Educational Institution';
  if (all.includes('bank') || all.includes('finance') || all.includes('invest')) return 'Financial Services';
  if (all.includes('health') || all.includes('medical') || all.includes('hospital')) return 'Healthcare / Medical';
  if (technologies.includes('React') || technologies.includes('Next.js') || technologies.includes('Vue.js')) return 'Modern Web Application';
  return 'General Website';
}

// ═══════════════════════════════════════════════════════════════
//  MAIN API ENDPOINT   POST /api/analyze
// ═══════════════════════════════════════════════════════════════
app.post('/api/analyze', async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'No target provided.' });

  const hostname = cleanHost(target);
  if (!hostname) return res.status(400).json({ error: 'Invalid target.' });

  try {
    // 1. Resolve IP
    let ip = isIP(hostname) ? hostname : await resolveIP(hostname);

    // 2. Parallel fetch: IP info, SSL cert, website scrape
    const [ipInfo, ssl, scrape] = await Promise.all([
      ip ? fetchIPInfo(ip)    : Promise.resolve(null),
      getSSLInfo(hostname),
      scrapeWebsite(hostname)
    ]);

    // If IP was not resolvable but scrape succeeded, try again via hostname
    if (!ip && scrape.hasSSL) ip = null;

    // 3. Scoring
    const { riskScore, riskLevel, trustScore, reasons } =
      calculateScores({ ipInfo, ssl, scrape, ip });

    // 4. Site classification
    const siteType = classifySiteType({
      technologies: scrape.technologies,
      title:        scrape.title,
      description:  scrape.description
    });

    // 5. Build response payload
    const report = {
      meta: {
        hostname,
        ip:          ip || 'Unresolvable',
        analyzedAt:  new Date().toISOString()
      },
      basicInfo: {
        domain:   hostname,
        ip:       ip || 'N/A',
        country:  ipInfo?.country        || 'Unknown',
        city:     ipInfo?.city           || 'Unknown',
        region:   ipInfo?.regionName     || 'Unknown',
        isp:      ipInfo?.isp            || 'Unknown',
        org:      ipInfo?.org            || 'Unknown',
        asn:      ipInfo?.as             || 'Unknown',
        latitude: ipInfo?.lat            || null,
        longitude:ipInfo?.lon            || null,
      },
      ipIntelligence: {
        ipType:      ipType(ip),
        isHosting:   ipInfo?.hosting ?? false,
        isProxy:     ipInfo?.proxy   ?? false,
        networkType: ipInfo?.hosting ? 'Hosting / Data Center' : 'Residential / Business'
      },
      riskAnalysis: {
        riskLevel,
        riskScore,
        reasons
      },
      ssl: ssl
        ? {
            enabled:    true,
            subject:    ssl.subject,
            issuer:     ssl.issuer,
            validFrom:  ssl.validFrom,
            validTo:    ssl.validTo,
            daysLeft:   ssl.daysLeft,
            isValid:    ssl.isValid,
            selfSigned: ssl.selfSigned
          }
        : { enabled: false },
      trustScore: {
        score: trustScore,
        factors: {
          sslValid:     ssl?.isValid   ?? false,
          noProxy:     !ipInfo?.proxy,
          hasMetadata:  !!(scrape.title || scrape.description),
          cfProtected:  scrape.technologies.includes('Cloudflare'),
          sslExists:    !!ssl
        }
      },
      websiteInfo: {
        title:        scrape.title       || 'Not found',
        description:  scrape.description || 'Not found',
        siteType,
        technologies: scrape.technologies,
        hasSSL:       scrape.hasSSL
      }
    };

    res.json({ success: true, report });

  } catch (err) {
    console.error('Analysis error:', err.message);
    res.status(500).json({ error: 'Analysis failed: ' + err.message });
  }
});

// Catch-all → serve frontend
app.get('*', (_, res) =>
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
);

app.listen(PORT, () =>
  console.log(`\n🛡  Site Analyzer running → http://localhost:${PORT}\n`)
);

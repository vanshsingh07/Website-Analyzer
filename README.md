# 🛡 SiteShield — Website Intelligence & Security Analyzer

A premium, glassmorphism-style multi-tab dashboard that lets you analyze any
domain or IP address for security risks, SSL status, geolocation, technology
fingerprints, and trust scoring.

---

## 📁 Project Structure

```
site-analyzer/
├── server.js              ← Node.js / Express backend (all analysis logic)
├── package.json           ← Project config & dependencies
└── public/
    ├── index.html         ← Single-page frontend shell
    ├── css/
    │   └── style.css      ← All styling (glassmorphism dark theme)
    └── js/
        └── script.js      ← All frontend JS (rendering, tabs, modal)
```

---

## 🚀 Setup Guide (Step-by-Step, Beginner Friendly)

### Step 1 — Install Node.js

Node.js is the runtime that powers the backend server.

1. Go to https://nodejs.org
2. Download the **LTS** (Long Term Support) version
3. Run the installer — accept all defaults
4. Open a terminal / command prompt and verify:

```
node --version    # should print v18.x.x or higher
npm --version     # should print 9.x.x or higher
```

---

### Step 2 — Set Up the Project

Open a terminal, navigate to where you saved this folder, and run:

```bash
cd site-analyzer
npm install
```

`npm install` reads `package.json` and downloads all required packages into a
`node_modules/` folder. This takes about 30 seconds.

Packages installed:
- **express**  — the web server framework
- **axios**    — makes HTTP requests (to ip-api, target sites)
- **cheerio**  — parses HTML like jQuery (for scraping titles, meta tags)
- **cors**     — allows cross-origin requests
- **node-whois** — WHOIS lookup support (optional extended use)
- **nodemon**  — (dev only) auto-restarts server on file changes

---

### Step 3 — Run the Server

```bash
node server.js
```

You should see:

```
🛡  Site Analyzer running → http://localhost:3000
```

Open your browser and go to: **http://localhost:3000**

> **For development** (auto-reload on changes):
> ```bash
> npx nodemon server.js
> ```

---

### Step 4 — Use the App

1. Type any domain (e.g. `github.com`) or IP (e.g. `8.8.8.8`) in the input
2. Click **Analyze** or press Enter
3. Watch the radar loading animation while the backend runs all checks
4. Explore the 5 tabs: Basic Info, IP Intel, Risk Analysis, SSL, Trust Score
5. Click **✦ View AI Intelligence Report** for the AI-powered popup

---

## 🔧 How It Works — Code Explained

### server.js

| Function | What it does |
|---|---|
| `cleanHost(raw)` | Strips http/https/www/paths to get a plain hostname |
| `isIP(str)` | Detects if the input is an IP address |
| `resolveIP(hostname)` | DNS lookup — converts domain → IP |
| `ipType(ip)` | Classifies IP as Public / Private / Loopback |
| `fetchIPInfo(ip)` | Calls ip-api.com to get country, city, ISP, proxy flag |
| `scrapeWebsite(hostname)` | Fetches the page, extracts title/description, fingerprints tech |
| `getSSLInfo(hostname)` | Opens a TLS socket and reads the certificate |
| `calculateScores(...)` | Risk + Trust scoring engine — explains WHY risk is high |
| `classifySiteType(...)` | Classifies site as blog/ecommerce/SaaS etc. |
| `POST /api/analyze` | Main endpoint — runs all checks in parallel, returns JSON |

### public/js/script.js

| Function | What it does |
|---|---|
| `startAnalysis()` | Reads input, calls `/api/analyze`, shows loading |
| `renderDashboard(r)` | Orchestrates all tab renders |
| `renderBasicInfo(r)` | Fills Basic Info tab with domain/IP/geo/tech |
| `renderIPIntel(r)` | Fills IP Intelligence tab with flags |
| `renderRisk(r)` | Animates SVG gauge, renders risk reasons |
| `renderSSL(r)` | Shows certificate details or "No SSL" warning |
| `renderTrust(r)` | Animates circle meter, renders stars + factors |
| `openModal()` | Opens modal and triggers report generation |
| `renderModalContent(r)` | Builds the AI intelligence narrative from report data |

---

## 🎨 Design System

The UI uses **glassmorphism** — a design style with:
- Semi-transparent frosted glass cards (`backdrop-filter: blur`)
- Dark background with glowing colour orbs
- Animated radar for loading
- SVG gauges for risk/trust scores
- Color coding: 🟢 Green = safe, 🟡 Yellow = medium, 🔴 Red = high risk

Fonts: **Syne** (display) + **DM Mono** (monospace data)

---

## 📡 APIs Used

| API | Purpose | Cost |
|---|---|---|
| [ip-api.com](http://ip-api.com) | Geolocation + proxy detection | Free (45 req/min) |
| Target website (direct) | HTML scraping + SSL handshake | N/A |
| Node built-in `dns` | Domain → IP resolution | N/A |
| Node built-in `tls` | Certificate inspection | N/A |

No API keys are required for the default setup.

---

## ⚠️ Common Issues

| Problem | Fix |
|---|---|
| `npm install` fails | Make sure Node.js is installed correctly |
| Port 3000 in use | Edit `server.js` line: `const PORT = 3001` |
| "Analysis failed" error | Target may block scraping — try another domain |
| SSL info missing | Some servers block TLS inspection; result shows "No SSL" |
| ip-api rate limit | Wait 1 minute, or add your ip-api Pro key |

---

## 🛠 Extending the Project

Some ideas for next steps:
- Add a database (SQLite/MongoDB) to cache and store past reports
- Add user authentication (JWT) to create accounts
- Export reports as PDF using `puppeteer`
- Add WHOIS lookup for domain registration date
- Integrate VirusTotal API for malware scanning
- Deploy to a cloud server (Railway, Render, Fly.io — all free tiers)

---

## 📄 License

MIT — use freely for personal and commercial projects.

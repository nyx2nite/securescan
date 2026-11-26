# SecureScan

A fast, dark-themed **website security scanner and security toolkit for Windows**. It runs as a desktop app (FastAPI + React in a native WebView2 window) and needs no account or login.

Enter a domain, URL or IP. SecureScan runs all checks in parallel, usually in 1–3 seconds. It scores the target out of 100 and gives a fix for every finding.

## Scanner checks

| Area | What is checked |
|---|---|
| **TLS / certificates** | Validity, chain trust, expiry countdown, protocol & cipher, SANs, self-signed, legacy TLS 1.0/1.1, HTTP→HTTPS redirect |
| **Network exposure** | 35 high-risk ports (RDP, SMB, databases, Redis, Docker API, Elasticsearch…) with banner grabbing |
| **Security headers** | CSP (incl. `unsafe-inline`/`unsafe-eval`), HSTS max-age, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **Sensitive files** | `.git`, `.env`, `.htpasswd`, SVN, backups & SQL dumps, `phpinfo`, `server-status`, phpMyAdmin, Spring actuator, `robots.txt` paths |
| **Web config** | CORS origin reflection (with credentials), TRACE, mixed content, insecure form actions, directory listing, version disclosure |
| **Cookies** | `Secure`, `HttpOnly`, `SameSite` flags |
| **DNS & email** | SPF (`-all`/`~all`/`+all`), DMARC policy, CAA records |
| **Fingerprinting** | Server, framework, CMS, CDN detection |

Results include a severity-ranked findings list with remediation, PDF and JSON export, rescans, and a dashboard. The dashboard shows score trends per target, a severity breakdown, the most common issues and certificate expiry.

## Toolbox

- **Recon:** DNS lookup, subdomain finder (passive, via Certificate Transparency), WHOIS / RDAP
- **Network:** custom port scanner (e.g. `1-1024`), TLS inspector, HTTP header & redirect inspector
- **Crypto:** hash generator (MD5 → SHA3), hash identifier, encoder/decoder (Base64, URL, hex, HTML, binary, ROT13), JWT decoder, and a password generator with strength and crack-time estimate

## Build the Windows app

Requirements: Python 3.11+, Node.js 18+, Windows 10/11 (WebView2 is built in).

```powershell
cd Backend
python -m venv venv
cd ..
powershell -ExecutionPolicy Bypass -File .\build_desktop.ps1
```

Output: `Backend\dist\SecureScan\SecureScan.exe`. Ship the whole `SecureScan` folder. Data (database and PDF reports) is stored in `%APPDATA%\SecureScan`.

## Development

```powershell
# backend (http://localhost:8000)
cd Backend
venv\Scripts\pip install -r requirements.txt
venv\Scripts\uvicorn main:app --reload

# frontend (http://localhost:5173, proxies /api to the backend)
cd Frontend
npm install
npm run dev
```

Or run the desktop window directly after `npm run build`: `Backend\venv\Scripts\python Backend\desktop.py`.

## Tech stack

FastAPI · SQLAlchemy (SQLite) · dnspython · ReportLab · React 19 · Vite · Tailwind CSS 4 · pywebview · PyInstaller

## Legal

Only scan systems you own or have explicit permission to test. Port scanning and probing for files without authorization may be illegal where you live.

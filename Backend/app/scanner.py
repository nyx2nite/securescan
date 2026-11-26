"""
SecureScan engine.

All checks run concurrently (thread pool) and share a single fetch of the target's
homepage, so a full scan typically completes in a few seconds.
"""
import ipaddress
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import requests
import urllib3

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:  # pragma: no cover
    HAS_DNS = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecureScan/2.0"
HTTP_TIMEOUT = 6

# ── Ports ──────────────────────────────────────────────────────
PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPCbind", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-Submission",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    2375: "Docker API", 3000: "Dev HTTP", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 6379: "Redis",
    8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB",
}
QUICK_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]

# Ports that should almost never be reachable from the internet
RISKY_PORTS = {
    23: ("high", "Telnet transmits credentials in cleartext."),
    21: ("medium", "FTP transmits credentials in cleartext."),
    135: ("medium", "MS-RPC exposure enables enumeration and lateral movement."),
    139: ("medium", "NetBIOS exposure leaks host information."),
    445: ("high", "SMB exposed to the internet (wormable vulns, e.g. EternalBlue)."),
    1433: ("high", "Database port exposed to the internet."),
    1521: ("high", "Database port exposed to the internet."),
    2375: ("high", "Unauthenticated Docker API allows full host takeover."),
    3306: ("high", "Database port exposed to the internet."),
    3389: ("high", "RDP exposed to the internet is a top ransomware entry point."),
    5432: ("high", "Database port exposed to the internet."),
    5900: ("high", "VNC exposed to the internet."),
    5985: ("medium", "WinRM exposed to the internet."),
    6379: ("high", "Redis is often unauthenticated and allows RCE."),
    9200: ("high", "Elasticsearch is often unauthenticated and leaks data."),
    11211: ("high", "Memcached can leak data and be abused for DDoS amplification."),
    27017: ("high", "MongoDB is often unauthenticated and leaks data."),
    2049: ("medium", "NFS exposed to the internet."),
    111: ("low", "RPCbind exposure aids enumeration."),
}

# ── Security headers (name, label, weight, remediation) ───────
SECURITY_HEADERS = [
    ("Content-Security-Policy", "CSP", 6, "Define a Content-Security-Policy to mitigate XSS and data injection."),
    ("Strict-Transport-Security", "HSTS", 6, "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."),
    ("X-Frame-Options", "X-Frame-Options", 4, "Add 'X-Frame-Options: DENY' (or CSP frame-ancestors) to prevent clickjacking."),
    ("X-Content-Type-Options", "X-Content-Type-Options", 3, "Add 'X-Content-Type-Options: nosniff'."),
    ("Referrer-Policy", "Referrer-Policy", 3, "Add 'Referrer-Policy: strict-origin-when-cross-origin'."),
    ("Permissions-Policy", "Permissions-Policy", 3, "Add a Permissions-Policy restricting camera, microphone, geolocation, etc."),
]

MAX_SCORES = {"https": 20, "headers": 25, "ports": 15, "cookies": 10, "config": 20, "dns": 10}


def get_status(score: int) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 70:
        return "Good"
    if score >= 50:
        return "Fair"
    return "Critical"


def finding(ftype, severity, title, description, remediation, category, **details):
    return {
        "type": ftype,
        "severity": severity,
        "description": description,
        "details": {"title": title, "remediation": remediation, "category": category, **details},
    }


def clean_target(raw: str) -> str:
    t = raw.strip()
    t = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", t)
    t = t.split("/")[0].split("?")[0].split("#")[0]
    if t.count(":") == 1:  # host:port
        t = t.split(":")[0]
    return t.strip(".").lower()


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def resolve_ip(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return "0.0.0.0"


# ── Ports ──────────────────────────────────────────────────────

def _probe_port(ip, port, timeout, grab_banner):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            banner = ""
            if grab_banner and port not in (80, 443, 8000, 8080, 8443, 3000):
                try:
                    s.settimeout(0.8)
                    banner = s.recv(160).decode("utf-8", "replace").strip()
                except OSError:
                    pass
            return port, True, banner
    except OSError:
        return port, False, ""


def scan_ports(ip: str, ports, timeout=1.0, grab_banner=True) -> dict:
    results = {}
    if ip == "0.0.0.0":
        return results
    with ThreadPoolExecutor(max_workers=min(200, max(1, len(ports)))) as ex:
        for port, open_, banner in ex.map(lambda p: _probe_port(ip, p, timeout, grab_banner), ports):
            results[str(port)] = {
                "port": port,
                "service": PORTS.get(port, "unknown"),
                "status": "open" if open_ else "closed",
                "banner": banner[:160],
            }
    return results


# ── TLS ────────────────────────────────────────────────────────

def _name_dict(seq):
    out = {}
    for rdn in seq or ():
        for k, v in rdn:
            out[k] = v
    return out


def inspect_tls(host: str, port: int = 443, check_legacy=True) -> dict:
    info = {"enabled": False, "certificate_valid": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                info.update(enabled=True, certificate_valid=True, protocol=ss.version(), cipher=ss.cipher()[0])
    except ssl.SSLCertVerificationError as e:
        info.update(enabled=True, error=e.verify_message or str(e))
        cert = None
    except Exception as e:
        info["error"] = str(e)
        return info

    if cert is None:
        # Retrieve details without verification
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    info.update(protocol=ss.version(), cipher=ss.cipher()[0])
                    der = ss.getpeercert(binary_form=True)
            pem = ssl.DER_cert_to_PEM_cert(der)
            # Decode with the stdlib's private helper (stable for years)
            import tempfile, os
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
                f.write(pem)
                tmp = f.name
            try:
                cert = ssl._ssl._test_decode_cert(tmp)
            finally:
                os.unlink(tmp)
        except Exception:
            cert = {}

    if cert:
        issuer = _name_dict(cert.get("issuer"))
        subject = _name_dict(cert.get("subject"))
        info["issuer"] = issuer
        info["subject"] = subject.get("commonName", "")
        info["san"] = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:50]
        if cert.get("notAfter"):
            info["expiry"] = cert["notAfter"]
            exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
            info["days_left"] = (exp - datetime.now(timezone.utc)).days
        if cert.get("notBefore"):
            info["valid_from"] = cert["notBefore"]
        info["self_signed"] = bool(issuer) and issuer == subject

    if check_legacy:
        info["legacy_protocols"] = _legacy_tls(host, port)
    return info


def _legacy_tls(host, port):
    supported = []
    for name, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            with socket.create_connection((host, port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    supported.append(name)
        except Exception:
            pass
    return supported


# ── HTTP ───────────────────────────────────────────────────────

def _session():
    s = requests.Session()
    s.headers["User-Agent"] = UA
    return s


def fetch_home(host: str):
    """Fetch the homepage once (HTTPS first, then HTTP). Returns (response, scheme)."""
    s = _session()
    for scheme in ("https", "http"):
        try:
            r = s.get(f"{scheme}://{host}", timeout=HTTP_TIMEOUT, allow_redirects=True, verify=False)
            return r, scheme
        except requests.RequestException:
            continue
    return None, None


def check_http_redirect(host: str) -> dict:
    try:
        r = _session().get(f"http://{host}", timeout=HTTP_TIMEOUT, allow_redirects=True, verify=False)
        chain = [h.url for h in r.history] + [r.url]
        return {"reachable": True, "redirects_to_https": r.url.startswith("https://"), "chain": chain}
    except requests.RequestException:
        return {"reachable": False, "redirects_to_https": None, "chain": []}


def analyze_headers(resp) -> dict:
    results = {}
    for name, label, _w, _r in SECURITY_HEADERS:
        value = resp.headers.get(name) if resp is not None else None
        entry = {"present": value is not None, "value": value if value is not None else "Missing"}
        notes = []
        if value:
            v = value.lower()
            if name == "Strict-Transport-Security":
                m = re.search(r"max-age=(\d+)", v)
                if not m or int(m.group(1)) < 15552000:
                    notes.append("max-age below 180 days")
            if name == "Content-Security-Policy":
                if "unsafe-inline" in v and "script-src" in v:
                    notes.append("allows 'unsafe-inline' scripts")
                if "unsafe-eval" in v:
                    notes.append("allows 'unsafe-eval'")
        entry["notes"] = notes
        results[label] = entry
    return results


def analyze_cookies(resp) -> dict:
    raw = []
    if resp is not None:
        for r in list(resp.history) + [resp]:
            try:
                raw += r.raw.headers.getlist("Set-Cookie")
            except Exception:
                pass
    cookies = []
    for line in raw:
        parts = [p.strip() for p in line.split(";")]
        name = parts[0].split("=", 1)[0]
        attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1)[1] if "=" in p else True) for p in parts[1:]}
        cookies.append({
            "name": name,
            "secure": "secure" in attrs,
            "httponly": "httponly" in attrs,
            "samesite": attrs.get("samesite", "None") if isinstance(attrs.get("samesite"), str) else "None",
            "domain": attrs.get("domain", "") if isinstance(attrs.get("domain"), str) else "",
        })
    return {"cookies": cookies, "count": len(cookies)}


TECH_SIGNATURES = [
    ("WordPress", r"wp-content|wp-includes"),
    ("Drupal", r"drupal-settings-json|/sites/default/files"),
    ("Joomla", r"/media/jui/|joomla"),
    ("Shopify", r"cdn\.shopify\.com"),
    ("Wix", r"static\.wixstatic\.com"),
    ("Next.js", r"__NEXT_DATA__|/_next/static"),
    ("Nuxt", r"__NUXT__|/_nuxt/"),
    ("React", r"data-reactroot|react-dom"),
    ("Angular", r"ng-version="),
    ("Vue.js", r"data-v-[0-9a-f]{6,}"),
    ("jQuery", r"jquery[.-]"),
    ("Bootstrap", r"bootstrap(\.min)?\.(css|js)"),
    ("Google Analytics", r"googletagmanager\.com|google-analytics\.com"),
    ("Cloudflare Turnstile/Challenge", r"challenges\.cloudflare\.com"),
    ("reCAPTCHA", r"google\.com/recaptcha"),
]


def fingerprint(resp) -> list:
    if resp is None:
        return []
    tech = []
    h = resp.headers
    for header in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "Via"):
        if h.get(header):
            tech.append({"name": h[header], "source": header})
    if h.get("CF-RAY"):
        tech.append({"name": "Cloudflare", "source": "CF-RAY"})
    if h.get("X-Amz-Cf-Id"):
        tech.append({"name": "Amazon CloudFront", "source": "X-Amz-Cf-Id"})
    if "x-vercel-id" in {k.lower() for k in h}:
        tech.append({"name": "Vercel", "source": "x-vercel-id"})
    body = resp.text[:300000] if resp.text else ""
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if m:
        tech.append({"name": m.group(1), "source": "meta generator"})
    for name, pattern in TECH_SIGNATURES:
        if re.search(pattern, body, re.I):
            tech.append({"name": name, "source": "page content"})
    seen, out = set(), []
    for t in tech:
        if t["name"] not in seen:
            seen.add(t["name"])
            out.append(t)
    return out


# Sensitive file exposure: (path, severity, title, validator)
EXPOSURE_CHECKS = [
    ("/.git/HEAD", "high", "Git repository exposed", lambda r: r.text.startswith("ref:")),
    ("/.git/config", "high", "Git config exposed", lambda r: "[core]" in r.text),
    ("/.env", "high", "Environment file (.env) exposed", lambda r: re.search(r"^[A-Z0-9_]{2,}=", r.text, re.M) is not None and "<html" not in r.text.lower()),
    ("/.svn/entries", "medium", "SVN metadata exposed", lambda r: r.text[:20].strip().isdigit() or "svn" in r.text[:200]),
    ("/.DS_Store", "low", ".DS_Store file exposed", lambda r: r.content[:8] == b"\x00\x00\x00\x01Bud1"),
    ("/.htpasswd", "high", ".htpasswd exposed", lambda r: re.search(r"^[^:\s<]+:\$?[\w./$]{10,}", r.text, re.M) is not None),
    ("/wp-config.php.bak", "high", "WordPress config backup exposed", lambda r: "DB_PASSWORD" in r.text),
    ("/config.php.bak", "high", "Config backup exposed", lambda r: "<?php" in r.text),
    ("/backup.zip", "high", "Backup archive exposed", lambda r: r.content[:2] == b"PK"),
    ("/backup.sql", "high", "SQL dump exposed", lambda r: "CREATE TABLE" in r.text or "INSERT INTO" in r.text),
    ("/dump.sql", "high", "SQL dump exposed", lambda r: "CREATE TABLE" in r.text or "INSERT INTO" in r.text),
    ("/server-status", "medium", "Apache server-status exposed", lambda r: "Apache Server Status" in r.text),
    ("/phpinfo.php", "medium", "phpinfo() page exposed", lambda r: "phpinfo()" in r.text or "PHP Version" in r.text),
    ("/info.php", "medium", "phpinfo() page exposed", lambda r: "phpinfo()" in r.text or "PHP Version" in r.text),
    ("/phpmyadmin/", "medium", "phpMyAdmin login exposed", lambda r: re.search(r'name=["\']pma_(username|password)', r.text) is not None),
    ("/actuator/env", "high", "Spring Boot actuator exposed", lambda r: "propertySources" in r.text),
    ("/.well-known/security.txt", "info", "security.txt present", lambda r: "Contact:" in r.text),
    ("/robots.txt", "info", "robots.txt present", lambda r: "user-agent" in r.text.lower()),
]


def check_exposure(base_url: str) -> list:
    s = _session()

    def probe(item):
        path, sev, title, validate = item
        try:
            r = s.get(base_url + path, timeout=5, allow_redirects=False, verify=False, stream=True)
            r._content = r.raw.read(65536, decode_content=True)
            if r.status_code == 200 and validate(r):
                entry = {"path": path, "severity": sev, "title": title, "status": r.status_code}
                if path == "/robots.txt":
                    entry["disallowed"] = re.findall(r"(?im)^disallow:\s*(\S+)", r.text)[:40]
                return entry
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=12) as ex:
        return [x for x in ex.map(probe, EXPOSURE_CHECKS) if x]


def check_methods_and_cors(base_url: str) -> dict:
    s = _session()
    out = {"allow": None, "trace_enabled": False, "cors": None}
    try:
        r = s.options(base_url, timeout=5, verify=False)
        out["allow"] = r.headers.get("Allow") or r.headers.get("Access-Control-Allow-Methods")
    except requests.RequestException:
        pass
    try:
        r = s.request("TRACE", base_url, timeout=5, verify=False, headers={"X-SecureScan-Trace": "1"})
        out["trace_enabled"] = r.status_code == 200 and "x-securescan-trace" in r.text.lower()
    except requests.RequestException:
        pass
    try:
        evil = "https://evil-securescan.example"
        r = s.get(base_url, timeout=5, verify=False, headers={"Origin": evil})
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = (r.headers.get("Access-Control-Allow-Credentials") or "").lower() == "true"
        out["cors"] = {"allow_origin": acao, "allow_credentials": acac, "reflects_origin": acao == evil}
    except requests.RequestException:
        pass
    return out


# ── DNS / Email ────────────────────────────────────────────────

def dns_lookup(domain: str, types=("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA")) -> dict:
    if not HAS_DNS:
        return {}
    res = dns.resolver.Resolver()
    res.lifetime = 4
    res.timeout = 2

    def q(rtype, name=domain):
        try:
            return rtype, [r.to_text() for r in res.resolve(name, rtype)]
        except Exception:
            return rtype, []

    with ThreadPoolExecutor(max_workers=len(types) + 1) as ex:
        futures = [ex.submit(q, t) for t in types]
        dmarc_f = ex.submit(q, "TXT", f"_dmarc.{domain}")
        records = dict(f.result() for f in futures)
        records["DMARC"] = [t.strip('"') for t in dmarc_f.result()[1] if "v=DMARC1" in t]
    return records


def analyze_email(records: dict) -> dict:
    spf = next((t.strip('"').replace('" "', "") for t in records.get("TXT", []) if "v=spf1" in t), None)
    dmarc = records.get("DMARC", [None])[0] if records.get("DMARC") else None
    policy = None
    if dmarc:
        m = re.search(r"p=(\w+)", dmarc)
        policy = m.group(1).lower() if m else None
    return {
        "has_mx": bool(records.get("MX")),
        "spf": spf,
        "spf_all": (re.search(r"([+~?-])all", spf).group(1) if spf and re.search(r"[+~?-]all", spf) else None),
        "dmarc": dmarc,
        "dmarc_policy": policy,
        "caa": bool(records.get("CAA")),
    }


# ── Findings & scoring ─────────────────────────────────────────

def build_findings(ctx) -> list:
    f = []
    tls, redirect, headers, cookies = ctx["tls"], ctx["redirect"], ctx["headers"], ctx["cookies"]
    resp, ports, exposure, mc, email = ctx["resp"], ctx["ports"], ctx["exposure"], ctx["methods"], ctx["email"]

    # TLS
    if not tls.get("enabled"):
        f.append(finding("no_https", "high", "HTTPS not available", "The site does not serve HTTPS on port 443.",
                         "Install a TLS certificate (e.g. free via Let's Encrypt) and serve all traffic over HTTPS.", "tls"))
    else:
        if not tls.get("certificate_valid"):
            f.append(finding("invalid_cert", "high", "Invalid TLS certificate", f"Certificate verification failed: {tls.get('error', 'unknown error')}",
                             "Use a certificate from a trusted CA that matches the hostname and includes the full chain.", "tls"))
        dl = tls.get("days_left")
        if dl is not None and dl < 0:
            f.append(finding("cert_expired", "high", "Certificate expired", f"The certificate expired {-dl} days ago.", "Renew the certificate and automate renewal.", "tls"))
        elif dl is not None and dl < 21:
            f.append(finding("cert_expiring", "medium", "Certificate expiring soon", f"The certificate expires in {dl} days.", "Renew the certificate and automate renewal (certbot, ACME).", "tls"))
        if tls.get("legacy_protocols"):
            f.append(finding("legacy_tls", "medium", "Legacy TLS versions enabled", f"Server accepts {', '.join(tls['legacy_protocols'])}, which are deprecated (RFC 8996).",
                             "Disable TLS 1.0 and 1.1; allow only TLS 1.2 and 1.3.", "tls"))
    if redirect.get("reachable") and redirect.get("redirects_to_https") is False and tls.get("enabled"):
        f.append(finding("no_https_redirect", "medium", "HTTP does not redirect to HTTPS", "Plain HTTP requests are served without redirecting to HTTPS.",
                         "Redirect all HTTP traffic to HTTPS with a 301 and enable HSTS.", "tls"))

    # Headers
    for name, label, weight, remediation in SECURITY_HEADERS:
        h = headers.get(label, {})
        if not h.get("present"):
            sev = "medium" if weight >= 6 else "low"
            f.append(finding("missing_header", sev, f"Missing {name}", f"The {name} response header is not set.", remediation, "headers", header=name))
        elif h.get("notes"):
            f.append(finding("weak_header", "low", f"Weak {name}", f"{name}: {'; '.join(h['notes'])}.", remediation, "headers", header=name, value=h.get("value")))

    # Cookies
    for c in cookies.get("cookies", []):
        missing = [flag for flag, ok in (("Secure", c["secure"]), ("HttpOnly", c["httponly"])) if not ok]
        if str(c.get("samesite", "None")).lower() == "none":
            missing.append("SameSite")
        if missing:
            f.append(finding("insecure_cookie", "medium" if "Secure" in missing else "low", f"Cookie '{c['name']}' missing flags",
                             f"Cookie '{c['name']}' is missing: {', '.join(missing)}.",
                             "Set cookies with Secure; HttpOnly; SameSite=Lax (or Strict).", "cookies", cookie=c["name"], missing=missing))

    # Ports
    for p in ports.values():
        if p["status"] == "open" and p["port"] in RISKY_PORTS:
            sev, why = RISKY_PORTS[p["port"]]
            f.append(finding("exposed_port", sev, f"Port {p['port']} ({p['service']}) open", why,
                             f"Restrict port {p['port']} with a firewall/security group, or expose it only via VPN.", "ports", port=p["port"], banner=p.get("banner")))

    # Server config
    if resp is not None:
        server = resp.headers.get("Server", "")
        if server and re.search(r"\d", server):
            f.append(finding("server_info", "low", "Server version disclosed", f"Server header reveals version: {server}",
                             "Hide version info (nginx: server_tokens off; Apache: ServerTokens Prod).", "config", server_header=server))
        xpb = resp.headers.get("X-Powered-By", "")
        if xpb:
            f.append(finding("powered_by", "low", "X-Powered-By disclosed", f"X-Powered-By header reveals: {xpb}",
                             "Remove the X-Powered-By header (PHP: expose_php = Off; Express: app.disable('x-powered-by')).", "config", x_powered_by=xpb))
        body = (resp.text or "")[:300000]
        if re.search(r"<title>\s*index of /", body, re.I):
            f.append(finding("directory_listing", "medium", "Directory listing enabled", "The server returns an auto-generated directory index.",
                             "Disable directory indexes (Apache: Options -Indexes; nginx: autoindex off).", "config", url=resp.url))
        if resp.url.startswith("https://"):
            for form in re.findall(r"<form[^>]*>", body, re.I):
                m = re.search(r'action=["\'](http://[^"\']*)', form, re.I)
                if m:
                    f.append(finding("insecure_form", "high", "Form submits over HTTP", "A form on an HTTPS page posts data over plain HTTP.",
                                     "Change form actions to HTTPS URLs.", "config", action=m.group(1)))
                    break
            mixed = re.findall(r'<script[^>]+src=["\'](http://[^"\']+)', body, re.I)
            if mixed:
                f.append(finding("mixed_content", "medium", "Mixed content (scripts over HTTP)", f"{len(mixed)} script(s) loaded over HTTP on an HTTPS page.",
                                 "Load all subresources over HTTPS.", "config", examples=mixed[:5]))

    if mc.get("trace_enabled"):
        f.append(finding("trace_enabled", "medium", "HTTP TRACE enabled", "The server echoes TRACE requests (Cross-Site Tracing).",
                         "Disable the TRACE method (Apache: TraceEnable off).", "config"))
    cors = mc.get("cors") or {}
    if cors.get("reflects_origin") and cors.get("allow_credentials"):
        f.append(finding("cors_reflect_creds", "high", "CORS reflects arbitrary origin with credentials",
                         "Any website can make authenticated cross-origin requests and read responses.",
                         "Validate Origin against an explicit allow-list; never reflect it with credentials enabled.", "config"))
    elif cors.get("reflects_origin"):
        f.append(finding("cors_reflect", "medium", "CORS reflects arbitrary origin", "Access-Control-Allow-Origin echoes any Origin header.",
                         "Use an explicit allow-list of trusted origins.", "config"))

    for e in exposure:
        if e["severity"] == "info":
            continue
        f.append(finding("exposed_file", e["severity"], e["title"], f"{e['path']} is publicly accessible.",
                         "Remove the file from the web root or deny access in the web server config.", "exposure", path=e["path"]))

    # DNS / email
    if email is not None and not ctx["is_ip"]:
        if email["has_mx"]:
            if not email["spf"]:
                f.append(finding("no_spf", "medium", "No SPF record", "Domain receives mail but publishes no SPF record, enabling spoofing.",
                                 "Publish a TXT record like 'v=spf1 include:<provider> -all'.", "dns"))
            elif email["spf_all"] in ("+", "?"):
                f.append(finding("weak_spf", "high" if email["spf_all"] == "+" else "medium", "Permissive SPF policy",
                                 f"SPF ends with '{email['spf_all']}all', which does not block spoofed senders.", "End the SPF record with '-all' (or '~all').", "dns"))
            if not email["dmarc"]:
                f.append(finding("no_dmarc", "medium", "No DMARC record", "No DMARC policy at _dmarc; spoofed mail is not rejected.",
                                 "Publish '_dmarc' TXT: 'v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain'.", "dns"))
            elif email["dmarc_policy"] == "none":
                f.append(finding("weak_dmarc", "low", "DMARC policy is 'none'", "DMARC only monitors; spoofed mail is still delivered.",
                                 "Move to p=quarantine or p=reject once reports look clean.", "dns"))
        if not email["caa"]:
            f.append(finding("no_caa", "info", "No CAA record", "Any certificate authority may issue certificates for this domain.",
                             "Publish CAA records restricting issuance to your CA (e.g. 0 issue \"letsencrypt.org\").", "dns"))
    return f


SEVERITY_PENALTY = {"critical": 8, "high": 6, "medium": 3, "low": 1, "info": 0}


def compute_scores(ctx, findings) -> dict:
    tls, redirect = ctx["tls"], ctx["redirect"]
    https = 0
    if tls.get("enabled"):
        https = 12 if tls.get("certificate_valid") else 4
        if not tls.get("legacy_protocols"):
            https += 4
        if redirect.get("redirects_to_https") or not redirect.get("reachable"):
            https += 4
    headers = sum(w for _n, label, w, _r in SECURITY_HEADERS if ctx["headers"].get(label, {}).get("present"))
    port_pen = sum({"high": 5, "medium": 3, "low": 1}[RISKY_PORTS[p["port"]][0]]
                   for p in ctx["ports"].values() if p["status"] == "open" and p["port"] in RISKY_PORTS)
    ports = max(0, 15 - port_pen)
    cl = ctx["cookies"].get("cookies", [])
    if cl:
        good = sum(c["secure"] + c["httponly"] + (str(c["samesite"]).lower() != "none") for c in cl)
        cookies = round(good / (3 * len(cl)) * 10)
    else:
        cookies = 10
    cfg_pen = sum(SEVERITY_PENALTY[x["severity"]] for x in findings if x["details"]["category"] in ("config", "exposure"))
    config = max(0, 20 - cfg_pen)
    email = ctx["email"]
    if email is None or ctx["is_ip"]:
        dns_score = 10
    else:
        dns_score = 2 if email["caa"] else 0
        if email["has_mx"]:
            dns_score += 4 if email["spf"] and email["spf_all"] in ("-", "~") else (2 if email["spf"] else 0)
            dns_score += 4 if email["dmarc_policy"] in ("quarantine", "reject") else (2 if email["dmarc"] else 0)
        else:
            dns_score += 8
    return {"https": https, "headers": headers, "ports": ports, "cookies": cookies, "config": config, "dns": dns_score}


# ── Main ───────────────────────────────────────────────────────

def run_scan(target: str, profile: str = "full") -> dict:
    started = time.perf_counter()
    host = clean_target(target)
    if not host:
        raise ValueError("Invalid target")
    full = profile != "quick"
    ip_target = is_ip(host)

    with ThreadPoolExecutor(max_workers=8) as ex:
        ip_f = ex.submit(resolve_ip, host)
        home_f = ex.submit(fetch_home, host)
        tls_f = ex.submit(inspect_tls, host, 443, full)
        redirect_f = ex.submit(check_http_redirect, host)
        dns_f = ex.submit(dns_lookup, host) if not ip_target else None
        ip = ip_f.result()
        ports_f = ex.submit(scan_ports, ip, list(PORTS) if full else QUICK_PORTS, 1.0, full)
        resp, scheme = home_f.result()
        base_url = f"{scheme}://{host}" if scheme else None
        exposure_f = ex.submit(check_exposure, base_url) if (full and base_url) else None
        methods_f = ex.submit(check_methods_and_cors, base_url) if (full and base_url) else None

        records = dns_f.result() if dns_f else {}
        ctx = {
            "is_ip": ip_target,
            "resp": resp,
            "tls": tls_f.result(),
            "redirect": redirect_f.result(),
            "ports": ports_f.result(),
            "exposure": exposure_f.result() if exposure_f else [],
            "methods": methods_f.result() if methods_f else {},
            "dns": records,
            "email": analyze_email(records) if records else None,
        }

    if ip == "0.0.0.0" and resp is None:
        raise ValueError(f"Could not resolve or reach '{host}'")

    ctx["headers"] = analyze_headers(resp)
    ctx["cookies"] = analyze_cookies(resp)
    findings = build_findings(ctx)
    breakdown = compute_scores(ctx, findings)
    total = sum(breakdown.values())
    status = get_status(total)

    details = {
        "ip": ip,
        "profile": profile,
        "duration_ms": int((time.perf_counter() - started) * 1000),
        "final_url": resp.url if resp is not None else None,
        "http_status": resp.status_code if resp is not None else None,
        "ports": ctx["ports"],
        "https": ctx["tls"],
        "redirect": ctx["redirect"],
        "headers": ctx["headers"],
        "raw_headers": dict(resp.headers) if resp is not None else {},
        "cookies": ctx["cookies"],
        "technologies": fingerprint(resp),
        "exposure": ctx["exposure"],
        "methods": ctx["methods"],
        "dns": records,
        "email": ctx["email"],
        "vulnerabilities": findings,
        "max_scores": MAX_SCORES,
    }
    return {
        "domain": host,
        "ip": ip,
        "score": total,
        "status": status,
        "scan_type": status.lower(),
        "breakdown": breakdown,
        "details": details,
        "vulnerabilities": findings,
    }

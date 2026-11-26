"""Standalone security tools exposed under /api/tools."""
import hashlib
import re
import socket
from concurrent.futures import ThreadPoolExecutor

import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.scanner import (
    PORTS, UA, clean_target, dns_lookup, analyze_email, inspect_tls, resolve_ip, scan_ports,
)

router = APIRouter(prefix="/tools")


def _host(value: str) -> str:
    host = clean_target(value or "")
    if not host or not re.fullmatch(r"[a-z0-9.\-:]+", host):
        raise HTTPException(400, "Invalid host")
    return host


def parse_ports(spec: str, limit=2048):
    spec = (spec or "").strip().lower()
    if spec in ("", "common"):
        return list(PORTS)
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            if a > b:
                a, b = b, a
            ports.update(range(max(1, a), min(65535, b) + 1))
        else:
            ports.add(int(part))
        if len(ports) > limit:
            raise HTTPException(400, f"Too many ports (max {limit} per scan)")
    return sorted(p for p in ports if 1 <= p <= 65535)


@router.get("/dns")
def tool_dns(domain: str):
    host = _host(domain)
    records = dns_lookup(host, ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA"))
    return {"domain": host, "records": records, "email": analyze_email(records)}


class PortScanRequest(BaseModel):
    host: str
    ports: str = "common"
    timeout: float = 0.8


@router.post("/ports")
def tool_ports(req: PortScanRequest):
    host = _host(req.host)
    try:
        ports = parse_ports(req.ports)
    except ValueError:
        raise HTTPException(400, "Invalid port list. Use e.g. 22,80,443 or 1-1024")
    ip = resolve_ip(host)
    if ip == "0.0.0.0":
        raise HTTPException(400, f"Could not resolve {host}")
    results = scan_ports(ip, ports, timeout=max(0.2, min(req.timeout, 3.0)), grab_banner=True)
    open_ports = [r for r in results.values() if r["status"] == "open"]
    return {"host": host, "ip": ip, "scanned": len(ports), "open": sorted(open_ports, key=lambda r: r["port"])}


@router.get("/tls")
def tool_tls(host: str, port: int = 443):
    return {"host": _host(host), "port": port, **inspect_tls(_host(host), port, True)}


@router.get("/headers")
def tool_headers(url: str, method: str = "GET"):
    url = url.strip()
    if not re.match(r"^https?://", url):
        url = "https://" + url
    try:
        r = requests.request(method.upper() if method.upper() in ("GET", "HEAD", "OPTIONS") else "GET",
                             url, timeout=8, allow_redirects=True, verify=False, headers={"User-Agent": UA})
    except requests.RequestException as e:
        raise HTTPException(400, f"Request failed: {e}")
    chain = [{"url": h.url, "status": h.status_code, "location": h.headers.get("Location")} for h in r.history]
    chain.append({"url": r.url, "status": r.status_code, "location": None})
    return {
        "url": r.url,
        "status": r.status_code,
        "elapsed_ms": int(r.elapsed.total_seconds() * 1000),
        "headers": dict(r.headers),
        "redirects": chain,
    }


@router.get("/subdomains")
def tool_subdomains(domain: str, resolve: bool = True):
    host = _host(domain)
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{host}&output=json", timeout=25, headers={"User-Agent": UA})
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        raise HTTPException(502, f"Certificate Transparency lookup failed (crt.sh): {e}")
    names = set()
    for entry in data:
        for n in str(entry.get("name_value", "")).split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n.endswith(host) and re.fullmatch(r"[a-z0-9.\-]+", n):
                names.add(n)
    names = sorted(names)[:500]
    results = [{"name": n, "ip": None} for n in names]
    if resolve and names:
        def res(n):
            try:
                return socket.gethostbyname(n)
            except OSError:
                return None
        with ThreadPoolExecutor(max_workers=50) as ex:
            for item, ip in zip(results, ex.map(res, names)):
                item["ip"] = ip
    return {"domain": host, "count": len(results), "subdomains": results}


@router.get("/whois")
def tool_whois(domain: str):
    host = _host(domain)
    try:
        r = requests.get(f"https://rdap.org/domain/{host}", timeout=15, headers={"User-Agent": UA, "Accept": "application/rdap+json"})
        if r.status_code == 404:
            raise HTTPException(404, "Domain not found in RDAP")
        r.raise_for_status()
        d = r.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"RDAP lookup failed: {e}")
    events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
    registrar = None
    for ent in d.get("entities", []):
        if "registrar" in ent.get("roles", []):
            vcard = ent.get("vcardArray", [None, []])[1]
            registrar = next((v[3] for v in vcard if v[0] == "fn"), None)
    return {
        "domain": d.get("ldhName", host).lower(),
        "registrar": registrar,
        "status": d.get("status", []),
        "nameservers": [ns.get("ldhName", "").lower() for ns in d.get("nameservers", [])],
        "created": events.get("registration"),
        "updated": events.get("last changed"),
        "expires": events.get("expiration"),
        "dnssec": (d.get("secureDNS") or {}).get("delegationSigned"),
    }


class HashRequest(BaseModel):
    text: str


@router.post("/hash")
def tool_hash(req: HashRequest):
    data = req.text.encode("utf-8")
    return {name: hashlib.new(name, data).hexdigest() for name in ("md5", "sha1", "sha256", "sha384", "sha512", "sha3_256")}

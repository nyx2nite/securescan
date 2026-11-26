import os
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
)

# The desktop app sets SECURESCAN_DATA_DIR to a writable per-user folder (%APPDATA%\SecureScan).
REPORTS_DIR = (
    os.path.join(os.environ["SECURESCAN_DATA_DIR"], "generated_reports")
    if os.getenv("SECURESCAN_DATA_DIR")
    else os.path.join(os.path.dirname(os.path.dirname(__file__)), "generated_reports")
)
os.makedirs(REPORTS_DIR, exist_ok=True)

DEFAULT_MAX = {"https": 20, "headers": 30, "ports": 20, "cookies": 15, "config": 15}
LABELS = {"https": "HTTPS / TLS", "headers": "Security Headers", "ports": "Network Exposure",
          "cookies": "Cookies", "config": "Server Configuration", "dns": "DNS & Email"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_COLOR = {"critical": "#7f1d1d", "high": "#dc2626", "medium": "#d97706", "low": "#2563eb", "info": "#6b7280"}


def _score_color(score: int):
    if score >= 90:
        return colors.HexColor("#16a34a")
    if score >= 70:
        return colors.HexColor("#2563eb")
    if score >= 50:
        return colors.HexColor("#d97706")
    return colors.HexColor("#dc2626")


def _table(rows, widths, font=9):
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), font),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def generate_pdf_report(scan_data: dict, username: str = "SecureScan") -> str:
    """Generate a PDF security report for a scan. Returns the file path."""
    domain = scan_data.get("domain", "unknown")
    score = scan_data.get("score", 0)
    status = scan_data.get("status", "")
    breakdown = scan_data.get("breakdown") or {}
    details = scan_data.get("details") or {}
    vulns = sorted(scan_data.get("vulnerabilities", []), key=lambda v: SEV_ORDER.get(v.get("severity"), 9))
    max_scores = details.get("max_scores") or DEFAULT_MAX
    scan_date = scan_data.get("date") or datetime.utcnow()

    filename = f"report_{domain.replace('.', '_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)
    doc = SimpleDocTemplate(filepath, pagesize=A4, topMargin=0.7 * inch, bottomMargin=0.7 * inch,
                            leftMargin=0.7 * inch, rightMargin=0.7 * inch)

    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle(name="T", parent=ss["Title"], fontSize=22, textColor=colors.HexColor("#111827")))
    ss.add(ParagraphStyle(name="H", parent=ss["Heading2"], fontSize=13, textColor=colors.HexColor("#111827"), spaceBefore=10, spaceAfter=6))
    ss.add(ParagraphStyle(name="B", parent=ss["BodyText"], fontSize=9, leading=12))
    ss.add(ParagraphStyle(name="S", parent=ss["BodyText"], fontSize=8, leading=10))
    P = lambda text, st="S": Paragraph(escape(str(text)), ss[st])

    el = [Paragraph("SecureScan — Security Assessment Report", ss["T"]),
          HRFlowable(width="100%", thickness=2, color=colors.HexColor("#111827")), Spacer(1, 10)]

    info = [["Target", domain], ["IP address", details.get("ip", scan_data.get("ip", "N/A"))],
            ["Scan date", scan_date.strftime("%Y-%m-%d %H:%M UTC")],
            ["Scan profile", str(details.get("profile", "full")).title()],
            ["Overall score", f"{score}/100  ({status})"]]
    t = Table(info, colWidths=[1.6 * inch, 5 * inch])
    t.setStyle(TableStyle([("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 10),
                           ("TEXTCOLOR", (1, 4), (1, 4), _score_color(score)), ("FONTNAME", (1, 4), (1, 4), "Helvetica-Bold"),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    el += [t, Spacer(1, 8)]

    # Executive summary
    counts = {s: sum(1 for v in vulns if v.get("severity") == s) for s in ("critical", "high", "medium", "low", "info")}
    summary = ", ".join(f"{n} {s}" for s, n in counts.items() if n) or "no issues"
    el.append(Paragraph(f"<b>Summary:</b> {len(vulns)} findings ({summary}).", ss["B"]))

    # Breakdown
    el.append(Paragraph("Score Breakdown", ss["H"]))
    rows = [["Category", "Score", "Max"]]
    for key, mx in max_scores.items():
        if key in breakdown:
            rows.append([LABELS.get(key, key), str(breakdown[key]), str(mx)])
    el.append(_table(rows, [3 * inch, 1 * inch, 1 * inch], 10))

    # Findings
    if vulns:
        el.append(Paragraph("Findings & Remediation", ss["H"]))
        rows = [["Severity", "Finding", "Remediation"]]
        for v in vulns:
            d = v.get("details") or {}
            sev = v.get("severity", "low")
            rows.append([
                Paragraph(f'<font color="{SEV_COLOR.get(sev, "#000")}"><b>{sev.upper()}</b></font>', ss["S"]),
                Paragraph(f"<b>{escape(d.get('title') or v.get('type', '').replace('_', ' ').title())}</b><br/>{escape(v.get('description', ''))}", ss["S"]),
                P(d.get("remediation", "—")),
            ])
        el.append(_table(rows, [0.8 * inch, 3.1 * inch, 2.9 * inch]))

    # TLS
    tls = details.get("https") or {}
    el.append(Paragraph("HTTPS / TLS", ss["H"]))
    issuer = tls.get("issuer") or {}
    rows = [["Property", "Value"],
            ["HTTPS enabled", "Yes" if tls.get("enabled") else "No"],
            ["Certificate valid", "Yes" if tls.get("certificate_valid") else f"No — {tls.get('error', '')}"[:90]],
            ["Protocol / cipher", f"{tls.get('protocol', '—')} / {tls.get('cipher', '—')}"],
            ["Issuer", issuer.get("organizationName") or issuer.get("commonName") or "—"],
            ["Expires", f"{tls.get('expiry', '—')}" + (f" ({tls['days_left']} days)" if tls.get("days_left") is not None else "")],
            ["Legacy TLS 1.0/1.1", ", ".join(tls.get("legacy_protocols") or []) or "Not accepted"]]
    el.append(_table([[P(a) if i else a for a in r] if i else r for i, r in enumerate(rows)], [1.8 * inch, 5 * inch]))

    # Open ports
    ports = details.get("ports") or {}
    open_ports = sorted((p for p in ports.values() if p.get("status") == "open"), key=lambda p: p.get("port", 0))
    el.append(Paragraph(f"Open Ports ({len(open_ports)} of {len(ports)} scanned)", ss["H"]))
    if open_ports:
        rows = [["Port", "Service", "Banner"]] + [[str(p["port"]), p.get("service", ""), P(p.get("banner") or "—")] for p in open_ports]
        el.append(_table(rows, [0.8 * inch, 1.6 * inch, 4.4 * inch]))
    else:
        el.append(P("No open ports detected.", "B"))

    # Headers
    headers = details.get("headers") or {}
    if headers:
        el.append(Paragraph("Security Headers", ss["H"]))
        rows = [["Header", "Status", "Value"]] + [
            [k, "Present" if v.get("present") else "Missing", P(str(v.get("value", ""))[:200])] for k, v in headers.items()]
        el.append(_table(rows, [1.6 * inch, 0.8 * inch, 4.4 * inch]))

    # Email security
    email = details.get("email")
    if email:
        el.append(Paragraph("DNS & Email Security", ss["H"]))
        rows = [["Record", "Value"], ["MX present", "Yes" if email.get("has_mx") else "No"],
                ["SPF", P(email.get("spf") or "Missing")], ["DMARC", P(email.get("dmarc") or "Missing")],
                ["CAA", "Present" if email.get("caa") else "Missing"]]
        el.append(_table(rows, [1.6 * inch, 5.2 * inch]))

    # Technologies
    tech = details.get("technologies") or []
    if tech:
        el.append(Paragraph("Detected Technologies", ss["H"]))
        el.append(P(", ".join(f"{t['name']} ({t['source']})" for t in tech), "B"))

    el += [Spacer(1, 14), HRFlowable(width="100%", thickness=0.5, color=colors.grey), Spacer(1, 4),
           Paragraph(f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} by SecureScan. "
                     "Only scan systems you own or are authorized to test.",
                     ParagraphStyle(name="F", parent=ss["BodyText"], fontSize=7, textColor=colors.grey))]
    doc.build(el)
    return filepath

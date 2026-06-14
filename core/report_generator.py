"""
A3 Security System — PDF Report Generator
Generates a professional security report you can hand to a client.
Covers: executive summary, threat timeline, network map,
top threats, DNS findings, recommendations.
"""

import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR    = Path(__file__).parent.parent
DATA_DIR    = BASE_DIR / "data"
DB_PATH     = DATA_DIR / "a3_threats.db"
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

def log(message, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colours = {"INFO":"\033[97m","OK":"\033[92m","WARN":"\033[93m"}
    print(f"[{ts}] {colours.get(level,'')}[REPORT][{level}]\033[0m {message}")

# ── Gather data from database ─────────────────────────────────────────────────

def gather_data(days=7):
    """Pull all relevant data for the report period."""
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    since = (datetime.now() - timedelta(days=days)).isoformat()
    data  = {}

    # Summary counts
    def count(table, where="1=1"):
        try:
            c.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}")
            return c.fetchone()[0]
        except Exception:
            return 0

    data["period_days"]        = days
    data["generated_at"]       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data["processes_scanned"]  = count("process_events", f"timestamp > '{since}'")
    data["files_sandboxed"]    = count("sandbox_reports", f"timestamp > '{since}'")
    data["malicious_found"]    = count("sandbox_reports",
                                       f"verdict='MALICIOUS' AND timestamp > '{since}'")
    data["suspicious_found"]   = count("sandbox_reports",
                                       f"verdict='SUSPICIOUS' AND timestamp > '{since}'")
    data["ai_assessments"]     = count("ai_assessments", f"timestamp > '{since}'")
    data["network_devices"]    = count("network_devices")
    data["high_risk_devices"]  = count("network_devices", "threat_score >= 50")
    data["blockchain_blocks"]  = count("blockchain")
    data["threat_intel_hashes"]= count("threat_hashes")
    data["threat_intel_ips"]   = count("threat_ips")
    data["threat_intel_domains"]= count("threat_domains")

    try:
        data["dns_queries"]    = count("dns_queries", f"timestamp > '{since}'")
        data["dns_suspicious"] = count("dns_queries",
                                       f"threat_score >= 30 AND timestamp > '{since}'")
    except Exception:
        data["dns_queries"]    = 0
        data["dns_suspicious"] = 0

    # Top threats
    try:
        c.execute("""
            SELECT aa.file_path, aa.verdict, aa.threat_type,
                   aa.threat_score, aa.recommended_action, aa.timestamp
            FROM ai_assessments aa
            WHERE aa.verdict IN ('MALICIOUS','SUSPICIOUS')
            AND aa.timestamp > ?
            ORDER BY aa.threat_score DESC LIMIT 10
        """, (since,))
        data["top_threats"] = [
            {"file": Path(r[0]).name, "verdict": r[1], "type": r[2],
             "score": r[3], "action": r[4], "time": r[5][:16]}
            for r in c.fetchall()
        ]
    except Exception:
        data["top_threats"] = []

    # Network devices
    try:
        c.execute("""
            SELECT ip, mac, vendor, hostname, threat_score, open_ports, flags
            FROM network_devices ORDER BY threat_score DESC LIMIT 15
        """)
        data["devices"] = []
        for r in c.fetchall():
            ports = json.loads(r[5]) if r[5] else []
            flags = json.loads(r[6]) if r[6] else []
            data["devices"].append({
                "ip": r[0], "mac": r[1], "vendor": r[2] or "Unknown",
                "hostname": r[3] or "—", "score": r[4],
                "ports": [p["service"] for p in ports],
                "flags": flags
            })
    except Exception:
        data["devices"] = []

    # Top suspicious DNS domains
    try:
        c.execute("""
            SELECT domain, query_count, max_score, last_seen
            FROM dns_stats WHERE max_score >= 30
            ORDER BY max_score DESC LIMIT 10
        """)
        data["dns_threats"] = [
            {"domain": r[0], "queries": r[1], "score": r[2], "last": r[3][:16]}
            for r in c.fetchall()
        ]
    except Exception:
        data["dns_threats"] = []

    # Blockchain summary
    try:
        c.execute("""
            SELECT block_index, timestamp, data FROM blockchain
            ORDER BY block_index DESC LIMIT 5
        """)
        data["recent_blocks"] = []
        for idx, ts, data_json in c.fetchall():
            d = json.loads(data_json)
            data["recent_blocks"].append({
                "index": idx, "time": ts[:16],
                "type": d.get("type", ""), "verdict": d.get("verdict", "")
            })
    except Exception:
        data["recent_blocks"] = []

    conn.close()
    return data

# ── PDF generation ────────────────────────────────────────────────────────────

def generate_pdf(data, output_path=None):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.colors import (HexColor, black, white,
                                           darkred, orange, green, grey)
        from reportlab.lib.units import cm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                         Table, TableStyle, HRFlowable,
                                         KeepTogether)
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    except ImportError:
        log("reportlab not installed. Run: pip install reportlab", "WARN")
        return None

    if not output_path:
        fname = f"A3_Security_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        output_path = REPORTS_DIR / fname

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm
    )

    # ── Colours ───────────────────────────────────────────────────────────────
    C_DARK    = HexColor("#0d1117")
    C_BLUE    = HexColor("#1e6fbf")
    C_RED     = HexColor("#c0392b")
    C_ORANGE  = HexColor("#e67e22")
    C_GREEN   = HexColor("#27ae60")
    C_GREY    = HexColor("#7f8c8d")
    C_LIGHT   = HexColor("#ecf0f1")
    C_WHITE   = white

    # ── Styles ────────────────────────────────────────────────────────────────
    styles = getSampleStyleSheet()

    def style(name, **kwargs):
        return ParagraphStyle(name, **kwargs)

    S_TITLE = style("title",
        fontSize=26, textColor=C_DARK, spaceAfter=4,
        fontName="Helvetica-Bold")
    S_SUB = style("sub",
        fontSize=11, textColor=C_GREY, spaceAfter=20,
        fontName="Helvetica")
    S_H1 = style("h1",
        fontSize=14, textColor=C_BLUE, spaceBefore=16, spaceAfter=6,
        fontName="Helvetica-Bold")
    S_H2 = style("h2",
        fontSize=11, textColor=C_DARK, spaceBefore=10, spaceAfter=4,
        fontName="Helvetica-Bold")
    S_BODY = style("body",
        fontSize=9, textColor=C_DARK, spaceAfter=4,
        fontName="Helvetica", leading=14)
    S_SMALL = style("small",
        fontSize=8, textColor=C_GREY,
        fontName="Helvetica")
    S_CENTER = style("center",
        fontSize=9, textColor=C_DARK, alignment=TA_CENTER,
        fontName="Helvetica")

    elements = []

    # ── Cover ─────────────────────────────────────────────────────────────────
    elements.append(Spacer(1, 1.5*cm))
    elements.append(Paragraph("A3 Security System", S_TITLE))
    elements.append(Paragraph("Security Assessment Report", style("s2",
        fontSize=18, textColor=C_BLUE, spaceAfter=6,
        fontName="Helvetica-Bold")))
    elements.append(Paragraph(
        f"Generated: {data['generated_at']}  •  "
        f"Period: Last {data['period_days']} days",
        S_SUB))
    elements.append(HRFlowable(width="100%", thickness=2,
                                color=C_BLUE, spaceAfter=20))

    # ── Executive Summary ─────────────────────────────────────────────────────
    elements.append(Paragraph("Executive Summary", S_H1))

    malicious = data["malicious_found"]
    risk_level = "HIGH" if malicious >= 3 else "MEDIUM" if malicious >= 1 else "LOW"
    risk_color = C_RED if risk_level == "HIGH" else C_ORANGE if risk_level == "MEDIUM" else C_GREEN

    summary_text = (
        f"During the reporting period, A3 monitored {data['processes_scanned']} "
        f"processes and sandboxed {data['files_sandboxed']} files. "
        f"<b>{malicious} malicious</b> and <b>{data['suspicious_found']} suspicious</b> "
        f"files were identified. "
        f"{data['network_devices']} devices were detected on the network, "
        f"{data['high_risk_devices']} of which are high-risk. "
        f"The threat intelligence database contains {data['threat_intel_hashes']:,} "
        f"known malware hashes, {data['threat_intel_ips']:,} malicious IPs, "
        f"and {data['threat_intel_domains']:,} malicious domains."
    )
    elements.append(Paragraph(summary_text, S_BODY))
    elements.append(Spacer(1, 0.3*cm))

    # Risk level badge
    risk_table = Table(
        [[Paragraph(f"Overall Risk Level: {risk_level}", style("rb",
            fontSize=13, textColor=C_WHITE, fontName="Helvetica-Bold",
            alignment=TA_CENTER))]],
        colWidths=[16*cm]
    )
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), risk_color),
        ("ROUNDEDCORNERS", [6]),
        ("TOPPADDING",    (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
    ]))
    elements.append(risk_table)
    elements.append(Spacer(1, 0.5*cm))

    # ── Key metrics grid ──────────────────────────────────────────────────────
    elements.append(Paragraph("Key Metrics", S_H1))

    def metric_cell(label, value, color=C_DARK):
        return [
            Paragraph(str(value), style("mv",
                fontSize=22, textColor=color, fontName="Helvetica-Bold",
                alignment=TA_CENTER)),
            Paragraph(label, style("ml",
                fontSize=8, textColor=C_GREY, fontName="Helvetica",
                alignment=TA_CENTER))
        ]

    metrics = Table([
        [metric_cell("Processes\nScanned",  data["processes_scanned"],  C_BLUE),
         metric_cell("Files\nSandboxed",    data["files_sandboxed"],    C_BLUE),
         metric_cell("Malicious\nFound",    data["malicious_found"],    C_RED),
         metric_cell("Suspicious\nFound",   data["suspicious_found"],   C_ORANGE)],
        [metric_cell("Network\nDevices",    data["network_devices"],    C_BLUE),
         metric_cell("High Risk\nDevices",  data["high_risk_devices"],  C_RED),
         metric_cell("DNS Queries\nLogged", data["dns_queries"],        C_BLUE),
         metric_cell("Blockchain\nBlocks",  data["blockchain_blocks"],  C_GREEN)],
    ], colWidths=[4*cm]*4)

    metrics.setStyle(TableStyle([
        ("BOX",         (0,0), (-1,-1), 0.5, C_LIGHT),
        ("INNERGRID",   (0,0), (-1,-1), 0.5, C_LIGHT),
        ("BACKGROUND",  (0,0), (-1,-1), HexColor("#f8f9fa")),
        ("TOPPADDING",  (0,0), (-1,-1), 10),
        ("BOTTOMPADDING",(0,0),(-1,-1), 10),
        ("ROUNDEDCORNERS", [4]),
    ]))
    elements.append(metrics)
    elements.append(Spacer(1, 0.5*cm))

    # ── Top threats table ─────────────────────────────────────────────────────
    if data["top_threats"]:
        elements.append(Paragraph("Threat Detections", S_H1))
        header = ["File", "Verdict", "Type", "Score", "Action", "Time"]
        rows   = [header]
        for t in data["top_threats"]:
            rows.append([
                t["file"][:30],
                t["verdict"],
                t["type"] or "—",
                str(t["score"]),
                t["action"],
                t["time"]
            ])

        threat_table = Table(rows, colWidths=[4.5*cm,2.2*cm,2.2*cm,1.5*cm,2.5*cm,3*cm])
        ts_style = [
            ("BACKGROUND",   (0,0), (-1,0),  C_DARK),
            ("TEXTCOLOR",    (0,0), (-1,0),  C_WHITE),
            ("FONTNAME",     (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",     (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_WHITE, HexColor("#f8f9fa")]),
            ("GRID",         (0,0), (-1,-1), 0.3, C_LIGHT),
            ("TOPPADDING",   (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0), (-1,-1), 5),
        ]
        # Colour verdict cells
        for i, t in enumerate(data["top_threats"], 1):
            col = C_RED if t["verdict"] == "MALICIOUS" else C_ORANGE
            ts_style.append(("TEXTCOLOR", (1,i), (1,i), col))
            ts_style.append(("FONTNAME",  (1,i), (1,i), "Helvetica-Bold"))

        threat_table.setStyle(TableStyle(ts_style))
        elements.append(threat_table)
        elements.append(Spacer(1, 0.5*cm))

    # ── Network devices ───────────────────────────────────────────────────────
    if data["devices"]:
        elements.append(Paragraph("Network Device Inventory", S_H1))
        header = ["IP Address", "Vendor", "Score", "Open Ports", "Flags"]
        rows   = [header]
        for d in data["devices"][:10]:
            rows.append([
                d["ip"],
                d["vendor"][:20],
                str(d["score"]),
                ", ".join(d["ports"][:4]) or "—",
                ", ".join(d["flags"][:2]) or "—"
            ])
        dev_table = Table(rows,
                          colWidths=[3*cm,3.5*cm,1.5*cm,4*cm,4*cm])
        dev_style = [
            ("BACKGROUND",   (0,0), (-1,0),  C_DARK),
            ("TEXTCOLOR",    (0,0), (-1,0),  C_WHITE),
            ("FONTNAME",     (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",     (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_WHITE, HexColor("#f8f9fa")]),
            ("GRID",         (0,0), (-1,-1), 0.3, C_LIGHT),
            ("TOPPADDING",   (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0), (-1,-1), 5),
        ]
        for i, d in enumerate(data["devices"][:10], 1):
            if d["score"] >= 50:
                dev_style.append(("TEXTCOLOR", (2,i), (2,i), C_RED))
                dev_style.append(("FONTNAME",  (2,i), (2,i), "Helvetica-Bold"))
        dev_table.setStyle(TableStyle(dev_style))
        elements.append(dev_table)
        elements.append(Spacer(1, 0.5*cm))

    # ── DNS threats ───────────────────────────────────────────────────────────
    if data["dns_threats"]:
        elements.append(Paragraph("Suspicious DNS Activity", S_H1))
        header = ["Domain", "Queries", "Risk Score", "Last Seen"]
        rows   = [header] + [
            [d["domain"][:45], str(d["queries"]),
             str(d["score"]), d["last"]]
            for d in data["dns_threats"]
        ]
        dns_table = Table(rows, colWidths=[7*cm,2.5*cm,2.5*cm,4*cm])
        dns_table.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,0),  C_DARK),
            ("TEXTCOLOR",    (0,0), (-1,0),  C_WHITE),
            ("FONTNAME",     (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",     (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_WHITE, HexColor("#f8f9fa")]),
            ("GRID",         (0,0), (-1,-1), 0.3, C_LIGHT),
            ("TOPPADDING",   (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0), (-1,-1), 5),
        ]))
        elements.append(dns_table)
        elements.append(Spacer(1, 0.5*cm))

    # ── Blockchain ────────────────────────────────────────────────────────────
    elements.append(Paragraph("Blockchain Evidence Ledger", S_H1))
    elements.append(Paragraph(
        f"All {data['blockchain_blocks']} threat records are cryptographically "
        f"chained and tamper-proof. Any modification to historical records "
        f"is immediately detectable via hash validation.",
        S_BODY
    ))
    if data["recent_blocks"]:
        header = ["Block #", "Type", "Verdict", "Timestamp"]
        rows   = [header] + [
            [str(b["index"]), b["type"], b["verdict"] or "—", b["time"]]
            for b in data["recent_blocks"]
        ]
        chain_table = Table(rows, colWidths=[2*cm,4*cm,3*cm,7*cm])
        chain_table.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,0),  C_DARK),
            ("TEXTCOLOR",    (0,0), (-1,0),  C_WHITE),
            ("FONTNAME",     (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",     (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_WHITE, HexColor("#f8f9fa")]),
            ("GRID",         (0,0), (-1,-1), 0.3, C_LIGHT),
            ("TOPPADDING",   (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0), (-1,-1), 5),
        ]))
        elements.append(chain_table)
        elements.append(Spacer(1, 0.5*cm))

    # ── Recommendations ───────────────────────────────────────────────────────
    elements.append(Paragraph("Recommendations", S_H1))
    recs = []
    if data["malicious_found"] > 0:
        recs.append(("HIGH", "Review and remove all quarantined malicious files immediately."))
    if data["high_risk_devices"] > 0:
        recs.append(("HIGH", f"Investigate {data['high_risk_devices']} high-risk network device(s). Consider network isolation."))
    if data["dns_suspicious"] > 0:
        recs.append(("MEDIUM", f"Review {data['dns_suspicious']} suspicious DNS queries for signs of data exfiltration."))
    if data["files_sandboxed"] == 0:
        recs.append(("LOW", "No files were sandboxed this period. Verify A3 monitor is active."))
    recs.append(("INFO", "Keep threat intelligence feeds updated — run python3 core/threat_feeds.py weekly."))
    recs.append(("INFO", "Validate blockchain integrity monthly — run python3 core/blockchain.py --validate."))
    recs.append(("INFO", "Retrain ML model after significant new threat data accumulates."))

    for priority, text in recs:
        col = C_RED if priority == "HIGH" else C_ORANGE if priority == "MEDIUM" else C_BLUE
        label = Table(
            [[Paragraph(f"[{priority}]", style("rl",
                fontSize=8, textColor=C_WHITE,
                fontName="Helvetica-Bold", alignment=TA_CENTER)),
              Paragraph(text, S_BODY)]],
            colWidths=[1.5*cm, 14.5*cm]
        )
        label.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (0,0), col),
            ("TOPPADDING",   (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",(0,0), (-1,-1), 4),
            ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ]))
        elements.append(label)
        elements.append(Spacer(1, 0.15*cm))

    # ── Footer ────────────────────────────────────────────────────────────────
    elements.append(Spacer(1, 1*cm))
    elements.append(HRFlowable(width="100%", thickness=1, color=C_LIGHT))
    elements.append(Spacer(1, 0.2*cm))
    elements.append(Paragraph(
        f"A3 Security System — Confidential — {data['generated_at']} — "
        f"All data stored locally. No cloud.",
        style("footer", fontSize=7, textColor=C_GREY,
              fontName="Helvetica", alignment=TA_CENTER)
    ))

    # Build PDF
    doc.build(elements)
    log(f"Report saved: {output_path}", "OK")
    return output_path

# ── Main ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    days = 7
    if "--days" in sys.argv:
        idx = sys.argv.index("--days")
        if len(sys.argv) > idx + 1:
            days = int(sys.argv[idx + 1])

    log(f"Generating {days}-day security report...")
    data = gather_data(days=days)
    path = generate_pdf(data)
    if path:
        print(f"\n  Report ready: {path}")
        # Open automatically on Mac
        import subprocess
        subprocess.run(["open", str(path)])
from io import BytesIO
from urllib.parse import urlparse
import datetime as dt

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.pdfgen import canvas

NAVY = colors.HexColor("#0B1728")
BLUE = colors.HexColor("#176B87")
CYAN = colors.HexColor("#20B8B0")
LIGHT = colors.HexColor("#F4F7F9")
MUTED = colors.HexColor("#526477")
BORDER = colors.HexColor("#CFD8DC")
RED = colors.HexColor("#C62828")
ORANGE = colors.HexColor("#E65100")
GREEN = colors.HexColor("#2E7D32")
HEADER_BG = colors.HexColor("#1A3A5F")

FEATURE_METADATA = {
    "url_length": ("Total URL Length", "Character count. Phishing campaigns frequently deploy long URLs (>75 chars) to obscure destination hostnames on mobile browsers."),
    "host_length": ("Hostname Length", "Length of destination host. Deceptive subdomains concatenate brand keywords to emulate trusted hosts."),
    "path_length": ("URI Path Length", "Length of request path. Deep paths are used to bypass static signature filters."),
    "dots": ("Hostname Dot Count", "Delimiters in host. Elevated dots indicate complex subdomain hierarchies emulating trusted brands."),
    "hyphens": ("Hyphen Count", "Hyphens in hostname. Attackers use hyphenated keywords (e.g., 'mits-portal') to mimic institutional identity."),
    "digits": ("Numeric Digit Count", "Digits in URL. Strongly correlates with automated, machine-generated disposable phishing links."),
    "special_chars": ("Special Character Count", "Count of symbols (@, =, _, %, ?, &). Elevated counts indicate query obfuscation or evasion tricks."),
    "subdomains": ("Subdomain Depth", "Number of nested subdomains isolating the authentic root domain from casual inspection."),
    "is_ip": ("IP Address Hostname", "Flags raw IP addresses (e.g. 192.168.1.1). Authentic consumer web services rarely direct users to raw IPs for logins."),
    "has_at": ("At Symbol (@) Delimiter", "Per RFC specs, browsers navigate strictly to the host following '@', ignoring preceding text."),
    "double_slash_path": ("Double Slash in Path (//)", "Exploited in open-redirect sequences and URL parsing bypasses."),
    "https": ("HTTPS Transport Protocol", "TLS encryption indicator (1=HTTPS, 0=HTTP). Encrypts transit but does not prove website legitimacy."),
    "shortener": ("URL Shortening Relay", "Flags URL shorteners (bit.ly, tinyurl) that obscure destination identity and redirect users."),
    "risky_tld": ("Higher-Risk Top-Level Domain", "Extensions (.xyz, .top, .click, .zip) favored in disposable phishing due to near-zero registration barriers."),
    "punycode": ("Punycode (xn--) Encoding", "Internationalized homoglyph domains exploiting lookalike characters to spoof authentic brands."),
    "suspicious_words": ("Suspicious Keyword Count", "Count of high-risk credential harvesting (login, verify) or urgency (suspended, alert) terms."),
    "suspicious_terms": ("Detected Keyword Tokens", "Specific high-risk social engineering keywords identified within path or query parameters."),
    "many_subdomains": ("Excessive Subdomains (>=3)", "Flags URLs with 3+ subdomain levels designed to conceal the real root domain."),
    "encoded": ("Percent-Encoded Sequences", "Excessive %xx hex sequences used to obfuscate hostile scripts from static inspection."),
    "host_entropy": ("Shannon Hostname Entropy", "Measures character randomness. High entropy (>3.5 bits) indicates algorithmically generated domains (DGA)."),
    "brand_typosquat": ("Brand Typosquatting Flag", "Levenshtein distance analysis detecting 1-character mutations of protected brands or institutions."),
    "typosquat_brand": ("Targeted Brand / Entity", "The authoritative brand or institution targeted by the detected lookalike domain mutation."),
    "has_executable_ext": ("Executable Payload Extension", "Detects binary executable file extensions (.exe, .scr, .apk, .zip, .bat) indicating malware drop."),
    "has_media_piracy": ("Media Piracy / Indexing Indicator", "Detects multimedia piracy tokens (music, mp3, torrent, crack, warez) frequently tied to adware."),
    "media_terms": ("Detected Media Keywords", "Specific media, piracy, or download keywords identified within URL components."),
    "malware_terms": ("Detected Malware Terminology", "High-risk exploit, backdoor, or trojan terminology identified in URL structure."),
    "is_free_hosting": ("Dynamic Free Cloud Hosting", "Disposable subdomains on free cloud platforms (Firebase, Pages.dev, Ngrok) abused for staging lures."),
    "has_static_html": ("Static Web Resource (.html)", "Direct static web resource extensions within deep or third-party URL paths."),
}


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas that computes total page count dynamically,
    rendering professional running headers and footers with 'Page X of Y'.
    """
    scan_id = "N/A"
    scan_url = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_decorations(self, page_count):
        self.saveState()
        # Running Header on page 2+
        if self._pageNumber > 1:
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(NAVY)
            self.drawString(16*mm, 285*mm, "PhishGuard Threat Intelligence Report")
            self.setFont("Helvetica", 7.5)
            self.setFillColor(MUTED)
            self.drawRightString(194*mm, 285*mm, f"Assessment #{self.scan_id} · Madanapalle Institute (MITS)")
            self.setStrokeColor(BORDER)
            self.setLineWidth(0.4)
            self.line(16*mm, 282*mm, 194*mm, 282*mm)

        # Running Footer on all pages
        self.setStrokeColor(BORDER)
        self.setLineWidth(0.4)
        self.line(16*mm, 14*mm, 194*mm, 14*mm)
        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(NAVY)
        self.drawString(16*mm, 9.5*mm, "PhishGuard")
        self.setFont("Helvetica", 7.5)
        self.setFillColor(MUTED)
        self.drawString(31*mm, 9.5*mm, "| Project System Developer: DEVARA SANDHYA (Academic Assessment 3-2)")
        self.drawRightString(194*mm, 9.5*mm, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


def _make_canvas(scan_id, scan_url):
    class DynamicNumberedCanvas(NumberedCanvas):
        pass
    DynamicNumberedCanvas.scan_id = str(scan_id)
    DynamicNumberedCanvas.scan_url = str(scan_url)
    return DynamicNumberedCanvas


def _table(rows, widths=(50*mm, 128*mm), header=False, alternate=True):
    table = Table(rows, colWidths=list(widths), repeatRows=1 if header else 0)
    styles = [
        ("GRID", (0, 0), (-1, -1), 0.45, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
    ]
    if header:
        styles += [
            ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("TOPPADDING", (0, 0), (-1, 0), 5.5),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 5.5),
        ]
    if alternate:
        for i in range(1 if header else 0, len(rows)):
            bg = LIGHT if i % 2 == 1 else colors.white
            styles.append(("BACKGROUND", (0, i), (-1, i), bg))
    table.setStyle(TableStyle(styles))
    return table


def build_pdf(r):
    out = BytesIO()
    doc = SimpleDocTemplate(
        out,
        pagesize=A4,
        rightMargin=16*mm,
        leftMargin=16*mm,
        topMargin=15*mm,
        bottomMargin=18*mm,
        title=f"PhishGuard Assessment #{r.get('id', 'N/A')}",
        author="DEVARA SANDHYA"
    )
    s = getSampleStyleSheet()
    s.add(ParagraphStyle(name="RepTitle", parent=s["Title"], textColor=NAVY, fontSize=18, leading=22, alignment=TA_CENTER, fontName="Helvetica-Bold"))
    s.add(ParagraphStyle(name="RepSubtitle", parent=s["Normal"], textColor=BLUE, fontSize=10, leading=14, alignment=TA_CENTER))
    s.add(ParagraphStyle(name="RepCredit", parent=s["Normal"], textColor=MUTED, fontSize=8, leading=11, alignment=TA_CENTER))
    s.add(ParagraphStyle(name="SecHeading", parent=s["Heading2"], textColor=NAVY, fontSize=11, leading=15, spaceBefore=8, spaceAfter=4, fontName="Helvetica-Bold", keepWithNext=True))
    s.add(ParagraphStyle(name="CellBody", parent=s["Normal"], fontSize=8, leading=11, textColor=NAVY))
    s.add(ParagraphStyle(name="CellBold", parent=s["Normal"], fontSize=8, leading=11, textColor=NAVY, fontName="Helvetica-Bold"))
    s.add(ParagraphStyle(name="CellMuted", parent=s["Normal"], fontSize=7.5, leading=10, textColor=MUTED))
    s.add(ParagraphStyle(name="BoxText", parent=s["Normal"], fontSize=8, leading=11.5, textColor=NAVY))
    s.add(ParagraphStyle(name="HeaderCell", parent=s["Normal"], fontSize=8, leading=11, textColor=colors.white, fontName="Helvetica-Bold"))

    story = [
        Paragraph("PhishGuard Threat Intelligence Report", s["RepTitle"]),
        Spacer(1, 1.5*mm),
        Paragraph("Automated Cybersecurity Threat Assessment, Heuristic Intelligence & Verification Audit", s["RepSubtitle"]),
        Spacer(1, 1*mm),
        Paragraph("Project System Developer: <b>DEVARA SANDHYA</b> &nbsp;|&nbsp; Academic Submission (MITS 3-2)", s["RepCredit"]),
        Spacer(1, 3.5*mm),
        Paragraph("1. Executive Threat Summary", s["SecHeading"])
    ]

    classification = r.get("classification", "Unknown")
    score = r.get("threat_score", 0.0)
    conf = r.get("confidence", 0.0)
    sev_color = RED if classification == "Phishing" else (ORANGE if classification == "Suspicious" else GREEN)

    summary_rows = [
        [Paragraph("Scan Reference", s["CellBold"]), Paragraph(f"#{r.get('id', 'Live Scan')}", s["CellBody"])],
        [Paragraph("Target URL Analyzed", s["CellBold"]), Paragraph(f"<b>{r.get('url', '')}</b>", s["CellBody"])],
        [Paragraph("Security Classification", s["CellBold"]), Paragraph(f"<b><font color='{sev_color.hexval()}'>{classification.upper()}</font></b>", s["CellBold"])],
        [Paragraph("Threat Risk Score", s["CellBold"]), Paragraph(f"<b>{score} / 100</b> ({'High Risk' if score > 60 else 'Moderate Risk' if score > 30 else 'Low Risk'})", s["CellBody"])],
        [Paragraph("Winning-Class Confidence", s["CellBold"]), Paragraph(f"<b>{conf}%</b> assessment probability", s["CellBody"])],
        [Paragraph("Analysis Timestamp", s["CellBold"]), Paragraph(str(r.get("created_at", dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))), s["CellBody"])],
    ]
    story.append(_table(summary_rows, (48*mm, 130*mm)))

    # Executive interpretation box
    if classification == "Phishing":
        interp = "<b>CRITICAL SECURITY WARNING:</b> This URL exhibits verified indicators of phishing or malicious deception. Do not enter institutional credentials, financial details, or personal data on this destination."
    elif classification == "Suspicious":
        interp = "<b>SECURITY ADVISORY:</b> Elevated risk signals were identified on this link. Exercise heightened vigilance and confirm authentic application context before proceeding."
    elif classification == "Security Test":
        interp = "<b>CONTROLLED SECURITY TEST:</b> Recognized official industry security evaluation test page (AMTSO). Safe for defensive verification."
    else:
        interp = "<b>LOW RISK ASSESSMENT:</b> The automated engine found no immediate threat signatures or credential harvesting vectors. Standard web hygiene remains recommended."
    
    story.append(Spacer(1, 1.5*mm))
    alert_table = Table([[Paragraph(interp, s["BoxText"])]], colWidths=[178*mm])
    alert_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
        ("BOX", (0, 0), (-1, -1), 1.0, sev_color),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 4.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
    ]))
    story.append(alert_table)

    # 2. Institutional Verification Card (if applicable)
    inst = r.get("institutional") or {}
    if inst.get("is_institutional"):
        story.append(Spacer(1, 2.5*mm))
        story.append(Paragraph("Institutional Verification & Governance (MITS Disambiguation)", s["SecHeading"]))
        inst_color = GREEN if inst.get("category") in {"Official", "Subdomain"} else (RED if inst.get("category") == "Phishing" else ORANGE)
        inst_rows = [
            [Paragraph("Institutional Status", s["CellBold"]), Paragraph(f"<b><font color='{inst_color.hexval()}'>{inst.get('status', 'Unknown')}</font></b>", s["CellBold"])],
            [Paragraph("Institution Identified", s["CellBold"]), Paragraph(inst.get("institution_name", "N/A"), s["CellBody"])],
            [Paragraph("Official Authority Ref", s["CellBold"]), Paragraph(inst.get("official_website_reference", "https://mits.ac.in/"), s["CellBody"])],
            [Paragraph("Institutional Evidence", s["CellBold"]), Paragraph(inst.get("evidence", ""), s["CellBody"])],
            [Paragraph("Verification Source", s["CellBold"]), Paragraph(inst.get("verification_source", "ERNET India / Official Registry"), s["CellBody"])],
        ]
        story.append(_table(inst_rows, (48*mm, 130*mm)))

    # 3. Domain & WHOIS/RDAP Evidence
    story.append(Spacer(1, 2.5*mm))
    story.append(Paragraph("2. Domain Identity & Authoritative Registration Evidence (WHOIS & RDAP)", s["SecHeading"]))
    
    parsed = urlparse(r.get("url", ""))
    host = parsed.hostname or ""
    domain = r.get("domain") or {}
    ssl_info = r.get("ssl") or {}
    bl = r.get("blacklist") or {}

    creation_date = domain.get("creation_date") or "N/A (Private or Unindexed Host)"
    age_str = domain.get("age_display") or "Unknown"
    if domain.get("age_days") is not None:
        age_str += f" ({domain['age_days']} days elapsed)"
    source_str = domain.get("source") or ("Authoritative RDAP / WHOIS" if domain.get("age_days") is not None else "Registry Unavailable")
    reg_domain = domain.get("registered_domain") or host

    evidence_rows = [
        [Paragraph("Target Hostname", s["CellBold"]), Paragraph(host, s["CellBody"])],
        [Paragraph("Registered Root Domain", s["CellBold"]), Paragraph(f"<b>{reg_domain}</b>", s["CellBody"])],
        [Paragraph("Authoritative Creation Date", s["CellBold"]), Paragraph(f"<b>{creation_date}</b> (Calculated from registry timestamp)", s["CellBody"])],
        [Paragraph("Domain Operational Age", s["CellBold"]), Paragraph(f"<b>{age_str}</b>", s["CellBody"])],
        [Paragraph("Attribution Data Protocol", s["CellBold"]), Paragraph(f"<b>{source_str}</b>", s["CellBody"])],
        [Paragraph("SSL/TLS Certificate State", s["CellBold"]), Paragraph(f"{ssl_info.get('status', 'Unknown')} (Valid: {ssl_info.get('valid')})", s["CellBody"])],
        [Paragraph("Certificate Expiration", s["CellBold"]), Paragraph(f"{ssl_info.get('days_remaining') or 'N/A'} days remaining", s["CellBody"])],
        [Paragraph("Reputation Feeds / Blacklist", s["CellBold"]), Paragraph(f"<b>{bl.get('status', 'Clean')}</b>", s["CellBody"])],
    ]
    story.append(_table(evidence_rows, (50*mm, 128*mm)))

    # Threat Intelligence Sources
    checks = bl.get("checks") or []
    if checks:
        story.append(Spacer(1, 2*mm))
        story.append(Paragraph("External Threat Intelligence Sources & Feed Checks", s["SecHeading"]))
        chk_rows = [
            [Paragraph("Security Source", s["HeaderCell"]), Paragraph("Status", s["HeaderCell"]), Paragraph("Timestamp (UTC)", s["HeaderCell"]), Paragraph("Verification Details", s["HeaderCell"])]
        ]
        for c in checks:
            c_stat = c.get("status", "Not Verified")
            c_color = RED if c_stat == "Listed" else (GREEN if c_stat in {"Clean", "Active"} else ORANGE)
            chk_rows.append([
                Paragraph(c.get("source", ""), s["CellBody"]),
                Paragraph(f"<b><font color='{c_color.hexval()}'>{c_stat}</font></b>", s["CellBold"]),
                Paragraph(c.get("timestamp", ""), s["CellMuted"]),
                Paragraph(c.get("details", ""), s["CellBody"]),
            ])
        story.append(_table(chk_rows, (42*mm, 24*mm, 34*mm, 78*mm), header=True))

    # 4. Security Modules
    story.append(Spacer(1, 2.5*mm))
    story.append(Paragraph("3. Security Risk Engine Module Breakdown", s["SecHeading"]))
    mod_rows = [
        [Paragraph("Security Risk Module", s["HeaderCell"]), Paragraph("Risk Score", s["HeaderCell"]), Paragraph("Security Interpretation", s["HeaderCell"])]
    ]
    for m_name, m_val in (r.get("module_scores") or {}).items():
        interp = "Low Risk / Clean Baseline" if m_val <= 30 else ("Moderate Caution / Signals Present" if m_val <= 60 else "High Threat Flag")
        mod_rows.append([
            Paragraph(m_name, s["CellBody"]),
            Paragraph(f"<b>{m_val} / 100</b>", s["CellBody"]),
            Paragraph(interp, s["CellBody"])
        ])
    story.append(_table(mod_rows, (55*mm, 35*mm, 88*mm), header=True))

    # 5. Detection Findings
    story.append(Spacer(1, 2.5*mm))
    story.append(Paragraph("4. Key Detection Findings (Prioritized Security Signals)", s["SecHeading"]))
    findings = r.get("findings") or []
    if findings:
        for idx, f in enumerate(findings, 1):
            f_sev = f.get("severity", "Informational")
            tag_color = RED if f_sev in {"Critical", "High"} else (ORANGE if f_sev == "Medium" else CYAN)
            f_box = [
                Paragraph(f"<b>{idx}. [{f['id']}] {f['title']}</b> &nbsp;&nbsp;[<font color='{tag_color.hexval()}'><b>{f_sev.upper()}</b></font>]", s["CellBold"]),
                Spacer(1, 0.8*mm),
                Paragraph(f["explanation"], s["CellBody"]),
                Spacer(1, 0.8*mm),
                Paragraph(f"<b>Technical Evidence:</b> {f['evidence']}", s["CellMuted"]),
                Paragraph(f"<b>Affected Component:</b> <font color='{BLUE.hexval()}'>{f['component']}</font> &nbsp;|&nbsp; <b>Action Plan:</b> Linked to <font color='{CYAN.hexval()}'>{f['recommendation_id']}</font>", s["CellMuted"]),
            ]
            f_table = Table([[f_box]], colWidths=[178*mm])
            f_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(KeepTogether([f_table, Spacer(1, 1.5*mm)]))
    else:
        for idx, item in enumerate(r.get("reasons", []), 1):
            story.append(Paragraph(f"{idx}. {item}", s["CellBody"]))

    # 6. Security Recommendations
    story.append(Spacer(1, 2.5*mm))
    story.append(Paragraph("5. Finding-Linked Security Recommendations", s["SecHeading"]))
    recommendations = r.get("recommendations") or []
    if recommendations and isinstance(recommendations[0], dict):
        for idx, rec in enumerate(recommendations, 1):
            rec_box = [
                Paragraph(f"<b>{idx}. [{rec['id']}] {rec['title']}</b> &nbsp;&nbsp;(Related Finding: <font color='{CYAN.hexval()}'>{rec['finding_id']}</font>)", s["CellBold"]),
                Spacer(1, 0.8*mm),
                Paragraph(f"<b>Risk Assessment:</b> {rec['risk']}", s["CellBody"]),
                Spacer(1, 0.8*mm),
                Paragraph(f"<b>Actionable Guidance:</b> <font color='{BLUE.hexval()}'><b>{rec['action']}</b></font>", s["CellBody"]),
            ]
            rec_table = Table([[rec_box]], colWidths=[178*mm])
            rec_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.5, CYAN),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(KeepTogether([rec_table, Spacer(1, 1.5*mm)]))
    else:
        for idx, item in enumerate(recommendations, 1):
            story.append(Paragraph(f"{idx}. {item}", s["CellBody"]))

    # 7. Extracted Lexical & Structural Features Guide (Compact Table)
    story.append(Spacer(1, 2.5*mm))
    story.append(Paragraph("6. Extracted Lexical & Structural Features", s["SecHeading"]))
    features = r.get("features") or {}
    if features:
        feat_rows = [
            [Paragraph("Indicator / Feature", s["HeaderCell"]), Paragraph("Observed Value", s["HeaderCell"]), Paragraph("Security Rationale & Role", s["HeaderCell"])]
        ]
        # Focus on key features to prevent 4+ pages of redundant filler
        key_features = [
            "url_length", "host_length", "subdomains", "is_ip", "has_at", "https",
            "shortener", "risky_tld", "suspicious_words", "brand_typosquat",
            "has_executable_ext", "has_media_piracy", "is_free_hosting", "host_entropy"
        ]
        for key in key_features:
            if key not in features:
                continue
            val = features[key]
            meta = FEATURE_METADATA.get(key)
            label = meta[0] if meta else key.replace("_", " ").title()
            explanation = meta[1] if meta else "Evaluated by Random Forest classifier."
            val_str = str(val)
            if isinstance(val, list):
                val_str = ", ".join(val) if val else "None"
            feat_rows.append([
                Paragraph(f"<b>{label}</b><br/><font color='{MUTED.hexval()}'>({key})</font>", s["CellBody"]),
                Paragraph(f"<b>{val_str}</b>", s["CellBold"]),
                Paragraph(explanation, s["CellBody"]),
            ])
        story.append(_table(feat_rows, (46*mm, 30*mm, 102*mm), header=True))

    # 8. Classification Probabilities & Methodology
    story.append(Spacer(1, 2.5*mm))
    story.append(Paragraph("7. Classification Probabilities & Inspection Methodology", s["SecHeading"]))
    prob_rows = [
        [Paragraph("Target Class", s["HeaderCell"]), Paragraph("Probability Confidence", s["HeaderCell"]), Paragraph("Mathematical Role", s["HeaderCell"])]
    ]
    for c_name, c_val in (r.get("probabilities") or {}).items():
        role = "Highest Confidence Winning Decision" if c_name == classification else "Alternative Hypothesis Probability"
        prob_rows.append([
            Paragraph(c_name, s["CellBody"]),
            Paragraph(f"<b>{c_val}%</b>", s["CellBold"]),
            Paragraph(role, s["CellBody"]),
        ])
    story.append(_table(prob_rows, (50*mm, 42*mm, 86*mm), header=True))

    story.append(Spacer(1, 2*mm))
    story.append(Paragraph("<b>Evaluation Methodology:</b> PhishGuard utilizes a multi-layered hybrid defense pipeline. URL lexical attributes are extracted and evaluated through a trained Random Forest classifier. Simultaneously, real-time network intelligence probes query authoritative WHOIS/RDAP registries for creation dates, perform live TLS handshake validation, inspect initial redirect hops, and consult threat intelligence feeds. The final operational threat score combines empirical penalties with probabilistic machine learning.", s["CellMuted"]))
    story.append(Spacer(1, 1*mm))
    story.append(Paragraph("<b>Notice:</b> Automated detection provides decision support. Threat actors continuously register newly crafted domains. Even if a score is low, always verify contextual legitimacy before transmitting sensitive information.", s["CellMuted"]))

    canvas_class = _make_canvas(r.get("id", "N/A"), r.get("url", ""))
    doc.build(story, canvasmaker=canvas_class)
    out.seek(0)
    return out

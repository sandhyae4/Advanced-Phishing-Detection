from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether

NAVY = colors.HexColor("#0B1728")
BLUE = colors.HexColor("#176B87")
CYAN = colors.HexColor("#20B8B0")
LIGHT = colors.HexColor("#EAF1F5")
MUTED = colors.HexColor("#526477")


def _table(rows, widths=(48*mm, 117*mm), header=False):
    table = Table(rows, colWidths=list(widths), repeatRows=1 if header else 0)
    styles = [("GRID", (0, 0), (-1, -1), .45, colors.HexColor("#B9C7D3")),
              ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 7),
              ("RIGHTPADDING", (0, 0), (-1, -1), 7), ("TOPPADDING", (0, 0), (-1, -1), 7),
              ("BOTTOMPADDING", (0, 0), (-1, -1), 7), ("BACKGROUND", (0, 0), (0, -1), LIGHT),
              ("TEXTCOLOR", (0, 0), (0, -1), NAVY)]
    if header:
        styles += [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                   ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]
    table.setStyle(TableStyle(styles))
    return table


def _header_footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(CYAN); canvas.line(18*mm, 14*mm, 192*mm, 14*mm)
    canvas.setFont("Helvetica", 8); canvas.setFillColor(MUTED)
    canvas.drawString(18*mm, 9*mm, "Advanced Phishing Detection & Threat Intelligence System")
    canvas.drawRightString(192*mm, 9*mm, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf(r):
    out = BytesIO()
    doc = SimpleDocTemplate(out, pagesize=A4, rightMargin=18*mm, leftMargin=18*mm,
                            topMargin=18*mm, bottomMargin=20*mm,
                            title=f"Phishing Assessment #{r['id']}", author="DEVARA SANDHYA")
    s = getSampleStyleSheet()
    s.add(ParagraphStyle(name="ReportTitle", parent=s["Title"], textColor=NAVY, fontSize=23, leading=28, alignment=TA_CENTER))
    s.add(ParagraphStyle(name="Section", parent=s["Heading2"], textColor=BLUE, fontSize=14, spaceBefore=12, spaceAfter=8))
    s.add(ParagraphStyle(name="Small", parent=s["BodyText"], fontSize=9, leading=13, textColor=colors.HexColor("#27394A")))
    s.add(ParagraphStyle(name="Note", parent=s["Small"], backColor=LIGHT, borderColor=CYAN, borderWidth=1,
                         borderPadding=8, spaceBefore=8, spaceAfter=8))
    story = [Paragraph("Advanced Phishing Detection", s["ReportTitle"]),
             Paragraph("Threat Intelligence & Cybersecurity Assessment Report", s["Heading2"]),
             Paragraph("Developed by <b>DEVARA SANDHYA</b>", ParagraphStyle("Credit", parent=s["Small"], alignment=TA_CENTER)),
             Spacer(1, 12), Paragraph("Executive summary", s["Section"])]
    summary = [["Scan reference", f"#{r['id']}"], ["URL analyzed", Paragraph(r["url"], s["Small"])],
               ["Final classification", r["classification"]], ["Threat score", f"{r['threat_score']} / 100"],
               ["Winning-class probability", f"{r['confidence']}%"], ["Scan timestamp (UTC)", r.get("created_at", "Not recorded")]]
    story += [_table(summary), Paragraph(
        f"The automated assessment classified this URL as <b>{r['classification']}</b> with a threat score of "
        f"<b>{r['threat_score']}/100</b>. The score combines lexical machine learning with domain, transport, "
        "reputation and blacklist evidence; it is not based on the ML probability alone.", s["Note"])]

    story += [Paragraph("Domain and threat-intelligence evidence", s["Section"])]
    evidence = [["SSL certificate", r["ssl"]["status"]], ["Certificate validity", str(r["ssl"].get("valid", "Unknown"))],
                ["Certificate days remaining", str(r["ssl"].get("days_remaining") or "Unknown")],
                ["Domain age", r["domain"]["age_display"]], ["Domain record status", r["domain"].get("status", "Unknown")],
                ["Reputation assessment", r["reputation"]], ["Blacklist status", r["blacklist"]["status"]],
                ["Providers queried", ", ".join(r["blacklist"].get("providers", [])) or "No external provider configured"]]
    story += [_table(evidence)]

    story += [Paragraph("Security module risk scores", s["Section"])]
    module_rows = [["Security module", "Risk score", "Interpretation"]]
    for name, value in r["module_scores"].items():
        meaning = "Low" if value <= 30 else "Moderate" if value <= 60 else "High"
        module_rows.append([name, f"{value}/100", meaning])
    story += [_table(module_rows, (75*mm, 35*mm, 55*mm), header=True)]

    story += [Paragraph("Classification probability", s["Section"])]
    prob_rows = [["Class", "Probability"]] + [[name, f"{value}%"] for name, value in r["probabilities"].items()]
    story += [_table(prob_rows, (100*mm, 65*mm), header=True),
              Paragraph("The highest probability is the confidence in the selected class. This differs from the threat score, which measures the severity of the detected risk evidence.", s["Small"]),
              PageBreak(), Paragraph("Detailed findings", s["Section"])]
    story += [Paragraph(f"{i}. {item}", s["Small"]) for i, item in enumerate(r["reasons"], 1)]
    story += [Paragraph("Security recommendations", s["Section"])]
    story += [Paragraph(f"{i}. {item}", s["Small"]) for i, item in enumerate(r["recommendations"], 1)]

    features = r.get("features") or {}
    story += [Paragraph("Extracted URL indicators", s["Section"])]
    if features:
        feature_rows = [["Indicator", "Observed value"]] + [[name.replace("_", " ").title(), str(value)] for name, value in features.items()]
        story += [_table(feature_rows, (100*mm, 65*mm), header=True)]
    else:
        story += [Paragraph("Not applicable to this recognized security-test page.", s["Small"])]

    story += [Paragraph("Assessment methodology", s["Section"]),
              Paragraph("The system validates and normalizes the URL, extracts structural indicators, checks suspicious vocabulary, URL shortening, IP-host and Punycode use, evaluates domain age and TLS state, queries configured intelligence providers, runs a Random Forest lexical classifier, and combines these signals using documented weighted scoring.", s["Small"]),
              Paragraph("Limitations and analyst note", s["Section"]),
              Paragraph("Automated URL analysis is decision support, not proof of safety. A legitimate site may host compromised content, newly created pages may lack reputation history, and external blacklist coverage depends on configured API keys. Do not enter credentials solely because this report gives a low score. Investigate redirects, page content and organizational context when the decision is high impact.", s["Note"]),
              Spacer(1, 12), Paragraph("Report generated by the Advanced Phishing Detection and Threat Intelligence System.", s["Small"])]
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    out.seek(0)
    return out

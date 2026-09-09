"""
Executive Snapshot PDF report — aggregate data only, matching the same
"raw host list is for your own responsible-disclosure use, never publish"
rule enforced everywhere else in this project. No specific IPs appear
anywhere in this report.
"""

import io
from datetime import date

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable, Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

NAVY = colors.HexColor("#141B2D")
DARK_BG = colors.HexColor("#0B0F19")
CYAN = colors.HexColor("#00D9C0")
TEXT_DARK = colors.HexColor("#1A1A2E")
MID_GREY = colors.HexColor("#5B6472")
LIGHT_GREY = colors.HexColor("#F2F4F5")
WHITE = colors.white

TIER_COLORS_HEX = {"Low": "#4C9F70", "Medium": "#E8B339", "High": "#E07B39", "Critical": "#FF3B3B"}
TIER_ORDER = ["Low", "Medium", "High", "Critical"]

TODAY = date.today().strftime("%d %B %Y")


def _chart_style(fig, ax):
    fig.patch.set_facecolor("#141B2D")
    ax.set_facecolor("#141B2D")
    ax.tick_params(colors="#B8C0CC", labelsize=9)
    for spine in ax.spines.values():
        spine.set_color("#2A3348")
    ax.title.set_color("#E5E7EB")
    ax.xaxis.label.set_color("#B8C0CC")
    ax.yaxis.label.set_color("#B8C0CC")


def _risk_tier_chart(hosts_df) -> bytes:
    counts = hosts_df["risk_tier"].value_counts().reindex(TIER_ORDER).fillna(0)
    fig, ax = plt.subplots(figsize=(6, 3.2), dpi=150)
    _chart_style(fig, ax)
    bar_colors = [TIER_COLORS_HEX[t] for t in TIER_ORDER]
    ax.bar(TIER_ORDER, counts.values, color=bar_colors, width=0.6)
    ax.set_title("Risk Tier Distribution (all products)", fontsize=11, pad=10)
    ax.set_ylabel("Hosts")
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", facecolor=fig.get_facecolor())
    plt.close(fig)
    buf.seek(0)
    return buf.read()


def _country_chart(hosts_df) -> bytes:
    top = hosts_df["country"].value_counts().head(10).sort_values()
    fig, ax = plt.subplots(figsize=(6, 3.6), dpi=150)
    _chart_style(fig, ax)
    ax.barh(top.index, top.values, color="#00D9C0", height=0.6)
    ax.set_title("Top 10 Countries by Exposed Host Count", fontsize=11, pad=10)
    ax.set_xlabel("Hosts")
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", facecolor=fig.get_facecolor())
    plt.close(fig)
    buf.seek(0)
    return buf.read()


def _product_chart(hosts_df) -> bytes:
    counts = hosts_df["product"].value_counts()
    fig, ax = plt.subplots(figsize=(6, 3.2), dpi=150)
    _chart_style(fig, ax)
    ax.bar(counts.index, counts.values, color="#5B8DEF", width=0.55)
    ax.set_title("Hosts by Product (this snapshot)", fontsize=11, pad=10)
    ax.set_ylabel("Hosts")
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", facecolor=fig.get_facecolor())
    plt.close(fig)
    buf.seek(0)
    return buf.read()


def _header_footer(canvas, doc):
    canvas.saveState()
    w, h = A4
    canvas.setFillColor(NAVY)
    canvas.rect(0, h - 18 * mm, w, 18 * mm, fill=True, stroke=False)
    canvas.setFillColor(CYAN)
    canvas.rect(0, h - 19.5 * mm, w, 1.5 * mm, fill=True, stroke=False)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.setFillColor(WHITE)
    canvas.drawString(15 * mm, h - 12 * mm, "Exposed AI Radar")
    canvas.drawRightString(w - 15 * mm, h - 12 * mm, "Executive Snapshot Report")
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, w, 12 * mm, fill=True, stroke=False)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#9AA4B2"))
    canvas.drawString(15 * mm, 4 * mm, f"Generated {TODAY} — aggregate data only, no host IPs included")
    canvas.drawRightString(w - 15 * mm, 4 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("TitleBig", fontSize=22, textColor=TEXT_DARK, spaceAfter=6,
                           fontName="Helvetica-Bold"))
    ss.add(ParagraphStyle("Subtitle", fontSize=11, textColor=MID_GREY, spaceAfter=16))
    ss.add(ParagraphStyle("H2c", fontSize=14, textColor=NAVY, spaceBefore=16, spaceAfter=8,
                           fontName="Helvetica-Bold"))
    ss.add(ParagraphStyle("Bodyc", fontSize=9.5, textColor=TEXT_DARK, leading=14, spaceAfter=6))
    ss.add(ParagraphStyle("Cellc", fontSize=8.5, textColor=TEXT_DARK, leading=11))
    ss.add(ParagraphStyle("KpiNum", fontSize=20, textColor=NAVY, fontName="Helvetica-Bold",
                           alignment=TA_CENTER))
    ss.add(ParagraphStyle("KpiLabel", fontSize=8, textColor=MID_GREY, alignment=TA_CENTER,
                           spaceAfter=0))
    return ss


def build_report_pdf(hosts_df, runs_df) -> bytes:
    ss = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=28 * mm, bottomMargin=20 * mm, leftMargin=18 * mm, rightMargin=18 * mm,
    )
    flow = []

    flow.append(Paragraph("Exposed AI Radar", ss["TitleBig"]))
    flow.append(Paragraph(
        "Executive Snapshot — passive, Shodan-based tracking of internet-exposed "
        "self-hosted AI inference tools. No host is ever contacted directly.",
        ss["Subtitle"],
    ))
    flow.append(HRFlowable(width="100%", thickness=0.75, color=colors.HexColor("#D0D5DD")))
    flow.append(Spacer(1, 12))

    # KPI row
    kpis = [
        (str(len(hosts_df)), "Hosts Tracked"),
        (str(int((hosts_df["risk_tier"] == "Critical").sum())), "Critical Risk"),
        (str(int((hosts_df["risk_tier"] == "High").sum())), "High Risk"),
        (str(int(hosts_df["country"].nunique())), "Countries"),
        (str(int(hosts_df["cve_kev"].sum())), "KEV-Confirmed"),
        (str(int((hosts_df["greynoise_classification"] == "malicious").sum())), "GreyNoise: Malicious"),
    ]
    kpi_table_data = [
        [Paragraph(num, ss["KpiNum"]) for num, _ in kpis],
        [Paragraph(label, ss["KpiLabel"]) for _, label in kpis],
    ]
    kpi_table = Table(kpi_table_data, colWidths=[(A4[0] - 36 * mm) / 6] * 6)
    kpi_table.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D5DD")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#EAECEF")),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GREY),
    ]))
    flow.append(kpi_table)
    flow.append(Spacer(1, 16))

    flow.append(Paragraph("Risk Overview", ss["H2c"]))
    flow.append(Image(io.BytesIO(_risk_tier_chart(hosts_df)), width=170 * mm, height=90 * mm))
    flow.append(Spacer(1, 8))
    flow.append(Image(io.BytesIO(_product_chart(hosts_df)), width=170 * mm, height=90 * mm))

    flow.append(Paragraph("Geographic Distribution", ss["H2c"]))
    flow.append(Image(io.BytesIO(_country_chart(hosts_df)), width=170 * mm, height=100 * mm))

    flow.append(Paragraph("Hosting Category Breakdown", ss["H2c"]))
    cat_counts = hosts_df["hosting_category"].value_counts()
    cat_data = [["Category", "Hosts", "% of Total"]]
    for cat, count in cat_counts.items():
        cat_data.append([cat, str(count), f"{100 * count / len(hosts_df):.1f}%"])
    cat_table = Table(cat_data, colWidths=[70 * mm, 40 * mm, 40 * mm])
    cat_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D5DD")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    flow.append(cat_table)
    flow.append(Spacer(1, 12))

    ollama = hosts_df[hosts_df["product"] == "Ollama"]
    flagged = ollama[ollama["cve_flags"].notna() & (ollama["cve_flags"] != "")]
    flow.append(Paragraph("Known-CVE Exposure (Ollama, version-based)", ss["H2c"]))
    flow.append(Paragraph(
        f"{len(flagged)} of {len(ollama)} sampled Ollama hosts are running a version affected by "
        f"at least one tracked CVE. {int(ollama['cve_kev'].sum())} confirmed in CISA's Known "
        f"Exploited Vulnerabilities catalog (actively exploited in the wild). Highest EPSS "
        f"(predicted exploitation probability) observed in this sample: "
        f"{ollama['cve_epss_max'].max():.2f}." if len(ollama) else "No Ollama hosts in this snapshot.",
        ss["Bodyc"],
    ))

    checked = hosts_df["greynoise_checked_at"].notna().sum()
    if checked:
        malicious = int((hosts_df["greynoise_classification"] == "malicious").sum())
        noisy = int(hosts_df["greynoise_noise"].fillna(0).astype(bool).sum())
        flow.append(Paragraph("Threat Intelligence Cross-Reference (GreyNoise)", ss["H2c"]))
        flow.append(Paragraph(
            f"{checked} Critical/High-risk host(s) cross-referenced against GreyNoise's "
            f"internet-scan telemetry (free Community API, budget-limited — not every "
            f"flagged host has been checked yet). {malicious} independently classified "
            f"<b>malicious</b> — a stronger signal than exposure alone, suggesting the box "
            f"may be compromised or repurposed rather than merely misconfigured. "
            f"{noisy} observed mass-scanning the internet themselves, regardless of "
            f"classification.",
            ss["Bodyc"],
        ))

    flow.append(Spacer(1, 16))
    flow.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#D0D5DD")))
    flow.append(Spacer(1, 8))
    flow.append(Paragraph(
        "<b>Methodology:</b> Data sourced entirely from Shodan's own pre-collected banner data, "
        "cross-referenced with LeakIX, Censys, and GreyNoise (each budget-limited and non-"
        "exhaustive — see project README). No discovered host is ever contacted directly. Risk "
        "tiers are a heuristic triage score (auth status, hosting category, known CVEs) — not an "
        "objective severity measure. This report contains aggregate statistics only; no specific "
        "IP addresses are included.",
        ss["Bodyc"],
    ))

    def on_page(canvas, doc_):
        _header_footer(canvas, doc_)

    doc.build(flow, onFirstPage=on_page, onLaterPages=on_page)
    buf.seek(0)
    return buf.read()

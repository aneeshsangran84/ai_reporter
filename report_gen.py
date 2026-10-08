"""
report_gen.py
-------------
Generates an executive-ready PDF report using FPDF2 + Matplotlib.
Robust against FPDFException: "Not enough horizontal space to render a single character".
"""

import os
import tempfile
from typing import Dict

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd
from fpdf import FPDF


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def _sanitize(text, max_len: int | None = None) -> str:
    """
    Make text safe for FPDF Helvetica / Latin-1 output.
    Never returns an empty string — FPDF crashes on empty multi_cell text.
    """
    if text is None:
        text = ""

    # Coerce to string, drop control chars, force latin-1
    text = str(text)
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = text.encode("latin-1", "replace").decode("latin-1")
    text = text.strip()

    if max_len and len(text) > max_len:
        text = text[: max_len - 3] + "..."

    return text if text else " "   # <-- key guard


def _safe_multi_cell(pdf: FPDF, text: str, height: int = 5) -> None:
    """
    Wrapper around multi_cell that always uses the full effective page width
    and resets X to the left margin first. Prevents the fpdf2 width bug.
    """
    pdf.set_x(pdf.l_margin)
    text = _sanitize(text)
    pdf.multi_cell(w=pdf.epw, h=height, txt=text)


def _chart_to_path(fig) -> str:
    """Save a Matplotlib figure to a temporary PNG and return the path."""
    fd, path = tempfile.mkstemp(suffix=".png")
    os.close(fd)
    fig.savefig(path, bbox_inches="tight", dpi=120)
    plt.close(fig)
    return path


def _severity_chart(df: pd.DataFrame) -> str:
    fig, ax = plt.subplots(figsize=(5, 3))
    counts = df["severity"].value_counts()
    ax.pie(counts.values, labels=counts.index, autopct="%1.0f%%")
    ax.set_title("Severity Distribution")
    return _chart_to_path(fig)


def _top_hosts_chart(df: pd.DataFrame) -> str:
    fig, ax = plt.subplots(figsize=(6, 3))
    counts = df["host_ip"].value_counts().head(10)
    ax.barh(counts.index[::-1], counts.values[::-1])
    ax.set_title("Top Vulnerable Hosts")
    ax.set_xlabel("Findings")
    return _chart_to_path(fig)


def _priority_chart(df: pd.DataFrame) -> str:
    fig, ax = plt.subplots(figsize=(5, 3))
    counts = df["ai_priority"].value_counts()
    ax.bar(counts.index, counts.values)
    ax.set_title("AI Triage Priority")
    ax.set_ylabel("Findings")
    return _chart_to_path(fig)


# ------------------------------------------------------------------
# Main report
# ------------------------------------------------------------------
def generate_pdf_report(df: pd.DataFrame, summary: Dict, top_n: int = 20) -> bytes:
    """Generate and return a PDF report as bytes."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ---- Title ----
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(w=pdf.epw, h=10, txt="AI Reporter - Executive Vulnerability Report")
    pdf.ln(14)

    # ---- Executive Summary ----
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(w=pdf.epw, h=8, txt="Executive Summary")
    pdf.ln(10)

    pdf.set_font("Helvetica", size=10)
    bullets = [
        f"Total findings: {summary.get('total', 0)}",
        f"Critical/High findings: {summary.get('critical_high', 0)}",
        f"Unique hosts affected: {summary.get('unique_hosts', 0)}",
        f"P1 immediate action: {summary.get('p1', 0)}",
        f"P2 scheduled maintenance: {summary.get('p2', 0)}",
        f"P3 informational/accepted risk: {summary.get('p3', 0)}",
    ]
    for b in bullets:
        _safe_multi_cell(pdf, f"- {b}", height=6)
    pdf.ln(4)

    # ---- Charts ----
    chart_paths = []
    try:
        if not df.empty:
            chart_paths.append(_severity_chart(df))
            chart_paths.append(_top_hosts_chart(df))
            chart_paths.append(_priority_chart(df))

        for path in chart_paths:
            pdf.set_x(pdf.l_margin)
            pdf.image(path, x=15, w=180)
            pdf.ln(2)
    finally:
        for p in chart_paths:
            try:
                os.remove(p)
            except OSError:
                pass

    # ---- Findings ----
    if not df.empty:
        pdf.add_page()
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(
            w=pdf.epw,
            h=8,
            txt=f"Top {min(top_n, len(df))} Triaged Findings",
        )
        pdf.ln(12)

        for i, (_, row) in enumerate(df.head(top_n).iterrows(), start=1):
            title = (
                f"{i}. [{row.get('ai_priority', 'N/A')}] "
                f"{row.get('plugin_name', 'Unknown Plugin')} "
                f"on {row.get('host_ip', 'Unknown Host')}"
            )
            pdf.set_font("Helvetica", "B", 10)
            _safe_multi_cell(pdf, title, height=6)

            pdf.set_font("Helvetica", size=9)
            meta = (
                f"AI Score: {float(row.get('ai_score', 0) or 0):.1f} | "
                f"Confidence: {float(row.get('ai_confidence', 0) or 0):.0%} | "
                f"CVSS: {float(row.get('cvss_score', 0) or 0):.1f} | "
                f"Severity: {row.get('severity', 'N/A')} | "
                f"CVE: {row.get('cve') or 'N/A'}"
            )
            _safe_multi_cell(pdf, meta, height=5)

            solution = (
                row.get("solution")
                or "Review vendor advisory and apply recommended remediation."
            )
            _safe_multi_cell(pdf, f"Solution: {solution}", height=5)
            pdf.ln(3)

    # ---- Output ----
    out = pdf.output(dest="S")
    if isinstance(out, str):
        return out.encode("latin-1")
    return bytes(out)

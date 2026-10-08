"""
app.py
------
Streamlit dashboard for AI Reporter.
"""

import streamlit as st
import pandas as pd
import plotly.express as px

import parser
import model as ai_model
import report_gen


st.set_page_config(
    page_title="AI Reporter",
    page_icon="🛡️",
    layout="wide",
)


@st.cache_resource
def load_ai_model():
    """Cache the trained AI model across Streamlit reruns."""
    return ai_model.get_triage_model()


def make_summary(df: pd.DataFrame) -> dict:
    """Build KPI summary dictionary."""
    if df is None or df.empty:
        return {
            "total": 0,
            "critical": 0,
            "high": 0,
            "critical_high": 0,
            "unique_hosts": 0,
            "p1": 0,
            "p2": 0,
            "p3": 0,
        }

    sev = df["severity"].fillna("Info").str.lower()

    return {
        "total": len(df),
        "critical": int((sev == "critical").sum()),
        "high": int((sev == "high").sum()),
        "critical_high": int(sev.isin(["critical", "high"]).sum()),
        "unique_hosts": int(df["host_ip"].nunique()),
        "p1": int((df["ai_priority"] == "P1").sum()),
        "p2": int((df["ai_priority"] == "P2").sum()),
        "p3": int((df["ai_priority"] == "P3").sum()),
    }


def generate_executive_summary(df: pd.DataFrame, summary: dict) -> list[str]:
    """Generate executive summary bullets."""
    if df is None or df.empty:
        return ["No findings available."]

    top_host = df["host_ip"].value_counts().idxmax()
    top_host_count = int(df["host_ip"].value_counts().max())

    top_plugin = df["plugin_name"].value_counts().idxmax()

    return [
        f"Scan contains {summary['total']} findings across {summary['unique_hosts']} unique hosts.",
        f"{summary['critical_high']} findings are Critical/High severity; {summary['p1']} are triaged as P1 immediate action.",
        f"Most affected host: {top_host} ({top_host_count} findings).",
        f"Most common finding: {top_plugin}.",
        "Prioritize P1 items first, then schedule P2 during maintenance windows; validate P3 as informational or accepted risk.",
    ]


def generate_cli_recommendations(df: pd.DataFrame) -> list[str]:
    """Generate terminal/admin remediation recommendations."""
    if df is None or df.empty:
        return ["# No findings available."]

    recs = []
    top = df.sort_values("ai_score", ascending=False).head(10)

    for _, row in top.iterrows():
        plugin = str(row.get("plugin_name", "")).lower()
        solution = str(row.get("solution", ""))
        host = row.get("host_ip", "unknown-host")

        if "openssh" in plugin or "ssh" in plugin:
            recs.append(
                f"# {host} - {row.get('plugin_name')}\n"
                f"sudo apt update && sudo apt install --only-upgrade openssh-server"
            )
        elif "apache" in plugin:
            recs.append(
                f"# {host} - {row.get('plugin_name')}\n"
                f"sudo apt update && sudo apt install --only-upgrade apache2"
            )
        elif "nginx" in plugin:
            recs.append(
                f"# {host} - {row.get('plugin_name')}\n"
                f"sudo apt update && sudo apt install --only-upgrade nginx"
            )
        elif "windows" in plugin or "smb" in plugin:
            recs.append(
                f"# {host} - {row.get('plugin_name')}\n"
                f"# Review vendor advisory and apply Windows security update"
            )
        else:
            recs.append(
                f"# {host} - {row.get('plugin_name')}\n"
                f"# Remediation: {solution[:180]}"
            )

    return recs[:10]


# -----------------------------
# Sidebar
# -----------------------------
with st.sidebar:
    st.title("🛡️ AI Reporter")
    st.caption("Automated Nessus Parser & AI Vulnerability Triage")

    uploaded_file = st.file_uploader(
        "Upload Nessus .nessus / .xml / .csv",
        type=["nessus", "xml", "csv"],
    )

    st.markdown("---")
    st.markdown("### Run locally")
    st.code(
        "pip install -r requirements.txt\nstreamlit run app.py",
        language="bash",
    )


if uploaded_file is None:
    st.title("🛡️ AI Reporter")
    st.info("Upload a Nessus `.nessus` XML or exported `.csv` report to begin.")
    st.stop()


# -----------------------------
# Parse + Triage
# -----------------------------
try:
    raw_df = parser.parse_file(uploaded_file.getvalue(), uploaded_file.name)
except Exception as exc:
    st.error(f"Failed to parse file: {exc}")
    st.stop()

if raw_df.empty:
    st.warning("No vulnerabilities found in the uploaded report.")
    st.stop()

with st.spinner("Running AI triage model..."):
    triaged_df = ai_model.triage_findings(raw_df, model=load_ai_model())

summary = make_summary(triaged_df)


# -----------------------------
# KPI Row
# -----------------------------
st.title("🛡️ AI Reporter")
st.caption("AI-prioritized Nessus findings, remediation guidance, and executive export.")

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Findings", summary["total"])
c2.metric("Critical / High", summary["critical_high"])
c3.metric("Unique Hosts", summary["unique_hosts"])
c4.metric("P1 Immediate", summary["p1"])


# -----------------------------
# Interactive Analytics
# -----------------------------
st.subheader("📊 Interactive Analytics")

chart_col1, chart_col2, chart_col3 = st.columns(3)

with chart_col1:
    sev_counts = triaged_df["severity"].value_counts().reset_index()
    sev_counts.columns = ["Severity", "Count"]
    fig_sev = px.pie(
        sev_counts,
        names="Severity",
        values="Count",
        hole=0.45,
        title="Severity Distribution",
    )
    st.plotly_chart(fig_sev, use_container_width=True)

with chart_col2:
    host_counts = triaged_df["host_ip"].value_counts().head(10).reset_index()
    host_counts.columns = ["Host", "Findings"]
    fig_host = px.bar(
        host_counts,
        x="Findings",
        y="Host",
        orientation="h",
        title="Top Vulnerable Hosts",
    )
    st.plotly_chart(fig_host, use_container_width=True)

with chart_col3:
    pri_counts = triaged_df["ai_priority"].value_counts().reset_index()
    pri_counts.columns = ["Priority", "Count"]
    fig_pri = px.bar(
        pri_counts,
        x="Priority",
        y="Count",
        color="Priority",
        title="AI Triage Priority",
    )
    st.plotly_chart(fig_pri, use_container_width=True)


# -----------------------------
# Filters + Data Table
# -----------------------------
st.subheader("🔎 Triage Data Table")

with st.expander("Filters", expanded=True):
    f1, f2, f3 = st.columns(3)

    severity_options = sorted(triaged_df["severity"].dropna().unique().tolist())
    priority_options = sorted(triaged_df["ai_priority"].dropna().unique().tolist())

    default_sev = [s for s in severity_options if s in ["Critical", "High"]]
    default_pri = [p for p in priority_options if p in ["P1", "P2"]]

    with f1:
        sev_filter = st.multiselect(
            "Severity",
            severity_options,
            default=default_sev or severity_options,
        )

    with f2:
        pri_filter = st.multiselect(
            "AI Priority",
            priority_options,
            default=default_pri or priority_options,
        )

    with f3:
        host_search = st.text_input("Host contains")

filtered = triaged_df.copy()

if sev_filter:
    filtered = filtered[filtered["severity"].isin(sev_filter)]

if pri_filter:
    filtered = filtered[filtered["ai_priority"].isin(pri_filter)]

if host_search:
    filtered = filtered[
        filtered["host_ip"].str.contains(host_search, case=False, na=False)
        | filtered["host_name"].str.contains(host_search, case=False, na=False)
    ]

display_cols = [
    "ai_priority",
    "ai_score",
    "ai_confidence",
    "host_ip",
    "host_name",
    "plugin_name",
    "severity",
    "cvss_score",
    "cve",
    "port",
    "protocol",
    "solution",
    "ai_reason",
]

available_cols = [c for c in display_cols if c in filtered.columns]

st.dataframe(
    filtered[available_cols],
    use_container_width=True,
    hide_index=True,
)


# -----------------------------
# AI Remediation Assistant
# -----------------------------
st.subheader("🤖 AI Remediation Assistant")

summary_bullets = generate_executive_summary(filtered, make_summary(filtered))
for bullet in summary_bullets:
    st.markdown(f"- {bullet}")

st.markdown("#### Recommended CLI / Admin Actions")
for cmd in generate_cli_recommendations(filtered):
    st.code(cmd, language="bash")


# -----------------------------
# PDF Export
# -----------------------------
st.subheader("📄 Export Report")

if st.button("Prepare PDF Report"):
    if filtered.empty:
        st.warning("No data to export after current filters.")
    else:
        with st.spinner("Generating PDF report..."):
            st.session_state["pdf_bytes"] = report_gen.generate_pdf_report(
                filtered,
                make_summary(filtered),
            )

if "pdf_bytes" in st.session_state:
    st.download_button(
        label="⬇️ Download PDF Report",
        data=st.session_state["pdf_bytes"],
        file_name="ai_reporter_executive_report.pdf",
        mime="application/pdf",
    )

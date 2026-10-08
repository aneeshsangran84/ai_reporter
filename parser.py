"""
parser.py
---------
Robust parser for Nessus .nessus XML and exported .csv reports.

Outputs a normalized Pandas DataFrame with the following key columns:
host_ip, host_name, plugin_id, plugin_name, risk_factor, severity,
severity_rank, cve, description, synopsis, solution, cvss_score,
cvss_vector, port, protocol, service, plugin_family, plugin_output.
"""

import io
import pandas as pd
import xml.etree.ElementTree as ET
from typing import Any, Dict, List


REQUIRED_COLUMNS = [
    "host_ip", "host_name", "plugin_id", "plugin_name", "risk_factor",
    "severity", "severity_rank", "cve", "description", "synopsis",
    "solution", "cvss_score", "cvss_vector", "port", "protocol",
    "service", "plugin_family", "plugin_output",
]

SEVERITY_RANK = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0,
}


def _clean(value: Any) -> str:
    """Return a clean string."""
    if value is None:
        return ""
    return str(value).strip()


def _severity_from_risk(value: Any) -> str:
    """Normalize Nessus risk/severity values to Critical/High/Medium/Low/Info."""
    s = _clean(value).lower()
    if s in {"critical", "4"}:
        return "Critical"
    if s in {"high", "3"}:
        return "High"
    if s in {"medium", "2"}:
        return "Medium"
    if s in {"low", "1"}:
        return "Low"
    if s in {"info", "informational", "none", "0", ""}:
        return "Info"
    return "Info"


def _text(parent: ET.Element, tag: str) -> str:
    """Safely extract text from an XML child tag."""
    child = parent.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return ""


def _first_text(parent: ET.Element, tags: List[str]) -> str:
    """Return the first non-empty text from a list of tags."""
    for tag in tags:
        val = _text(parent, tag)
        if val:
            return val
    return ""


def _host_props(host: ET.Element) -> Dict[str, str]:
    """Extract HostProperties tags into a dictionary."""
    props: Dict[str, str] = {}
    hp = host.find("HostProperties")
    if hp is not None:
        for tag in hp.findall("tag"):
            name = tag.attrib.get("name", "")
            props[name] = (tag.text or "").strip()
    return props


def normalize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize parsed data and enforce expected schema."""
    if df is None or df.empty:
        return pd.DataFrame(columns=REQUIRED_COLUMNS)

    out = df.copy()

    for col in REQUIRED_COLUMNS:
        if col not in out.columns:
            out[col] = ""

    # Normalize severity/risk fields
    out["risk_factor"] = out["risk_factor"].apply(_severity_from_risk)
    out["severity"] = out["severity"].apply(_severity_from_risk)

    # If severity ended up Info but risk_factor is stronger, prefer risk_factor
    out.loc[out["severity"] == "Info", "severity"] = out.loc[
        out["severity"] == "Info", "risk_factor"
    ]

    out["severity_rank"] = out["severity"].map(SEVERITY_RANK).fillna(0).astype(int)
    out["cvss_score"] = (
        pd.to_numeric(out["cvss_score"], errors="coerce")
        .fillna(0.0)
        .clip(0, 10)
    )

    string_cols = [
        "host_ip", "host_name", "plugin_id", "plugin_name", "cve",
        "description", "synopsis", "solution", "cvss_vector", "port",
        "protocol", "service", "plugin_family", "plugin_output",
    ]
    for col in string_cols:
        out[col] = out[col].fillna("").astype(str)

    return out[REQUIRED_COLUMNS]


def parse_nessus_xml(content: bytes) -> pd.DataFrame:
    """Parse Nessus .nessus XML content."""
    root = ET.fromstring(content)
    rows = []

    for host in root.iter("ReportHost"):
        host_attr_name = host.attrib.get("name", "")
        props = _host_props(host)

        host_ip = props.get("host-ip") or props.get("ip") or host_attr_name
        host_name = props.get("host-fqdn") or props.get("hostname") or host_attr_name

        for item in host.findall("ReportItem"):
            attrib = item.attrib

            risk = _text(item, "risk_factor") or _severity_from_risk(
                attrib.get("severity")
            )
            severity = _severity_from_risk(risk)

            cves = ", ".join(
                [
                    c.text.strip()
                    for c in item.findall("cve")
                    if c.text and c.text.strip()
                ]
            )

            cvss = _first_text(
                item,
                [
                    "cvss3_base_score",
                    "cvss4_base_score",
                    "cvss_base_score",
                    "cvss2_base_score",
                ],
            )
            vector = _first_text(
                item,
                [
                    "cvss3_vector",
                    "cvss4_vector",
                    "cvss_vector",
                    "cvss2_vector",
                ],
            )

            rows.append(
                {
                    "host_ip": host_ip,
                    "host_name": host_name,
                    "plugin_id": attrib.get("pluginID", ""),
                    "plugin_name": attrib.get("pluginName", ""),
                    "risk_factor": risk,
                    "severity": severity,
                    "cve": cves,
                    "description": _text(item, "description"),
                    "synopsis": _text(item, "synopsis"),
                    "solution": _text(item, "solution"),
                    "cvss_score": cvss,
                    "cvss_vector": vector,
                    "port": attrib.get("port", ""),
                    "protocol": attrib.get("protocol", ""),
                    "service": attrib.get("svc_name", ""),
                    "plugin_family": attrib.get("pluginFamily", ""),
                    "plugin_output": _text(item, "plugin_output"),
                }
            )

    return normalize_dataframe(pd.DataFrame(rows))


def _find_col(df: pd.DataFrame, aliases: List[str]) -> str | None:
    """Find a CSV column by case-insensitive aliases."""
    lower_map = {
        str(c).strip().lower().replace("\ufeff", ""): c for c in df.columns
    }
    for alias in aliases:
        key = alias.lower()
        if key in lower_map:
            return lower_map[key]
    return None


def parse_csv(content: bytes) -> pd.DataFrame:
    """Parse Nessus-exported CSV content."""
    df = pd.read_csv(io.BytesIO(content))

    def get(aliases: List[str], default: str = ""):
        col = _find_col(df, aliases)
        return df[col] if col is not None else default

    out = pd.DataFrame()

    out["host_ip"] = get(["host", "host ip", "ip", "ip address"])
    out["host_name"] = get(["host name", "dns name", "fqdn"])
    out["plugin_id"] = get(["plugin id", "plugin_id", "pluginid"])
    out["plugin_name"] = get(["plugin name", "name"])
    out["risk_factor"] = get(["risk", "risk factor", "severity"])
    out["severity"] = out["risk_factor"]
    out["cve"] = get(["cve"])
    out["description"] = get(["description"])
    out["synopsis"] = get(["synopsis"])
    out["solution"] = get(["solution"])
    out["cvss_score"] = get(
        [
            "cvss v3.0 base score",
            "cvss3 base score",
            "cvss v4.0 base score",
            "cvss4 base score",
            "cvss v2.0 base score",
            "cvss base score",
            "cvss",
        ]
    )
    out["cvss_vector"] = get(
        [
            "cvss v3.0 vector",
            "cvss3 vector",
            "cvss v4.0 vector",
            "cvss4 vector",
            "cvss vector",
        ]
    )
    out["port"] = get(["port"])
    out["protocol"] = get(["protocol"])
    out["service"] = get(["service", "svc_name"])
    out["plugin_family"] = get(["plugin family", "family"])
    out["plugin_output"] = get(["plugin output", "output"])

    return normalize_dataframe(out)


def parse_file(content: bytes, filename: str) -> pd.DataFrame:
    """
    Main entry point. Parses .nessus/.xml or .csv based on filename.
    Falls back to XML then CSV if extension is unknown.
    """
    lower = filename.lower()

    if lower.endswith(".csv"):
        return parse_csv(content)

    if lower.endswith((".nessus", ".xml")):
        return parse_nessus_xml(content)

    # Fallback: try XML first, then CSV
    try:
        return parse_nessus_xml(content)
    except Exception:
        return parse_csv(content)

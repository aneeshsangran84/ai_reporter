# 🛡️ AI Reporter

**Automated Nessus Scan Parser & AI-Driven Vulnerability Triage System**

AI Reporter is a Streamlit-based web utility that ingests Nessus `.nessus` XML or exported `.csv` reports, parses and structures raw vulnerability data, uses machine learning / NLP to dynamically prioritize findings beyond static CVSS scores, and exports an executive-ready PDF report complete with remediation steps.

---

## ✨ Features

- 📥 **Drag-and-drop upload** for `.nessus`, `.xml`, and `.csv` Nessus reports
- 🧩 **Robust parser** for XML and CSV, with column-alias handling across Nessus versions
- 🧠 **AI/ML triage engine** (TF-IDF + Random Forest) that classifies findings into:
  - **P1** — Critical / Immediate Patch Required
  - **P2** — Scheduled Maintenance
  - **P3** — Informational / False Positive / Acceptable Risk
- 📊 **Interactive analytics** with Plotly:
  - Severity distribution (pie)
  - Top vulnerable hosts (bar)
  - AI triage priority breakdown (bar)
- 📈 **KPI dashboard**: total findings, critical/high count, unique hosts, P1 count
- 🔎 **Filterable triage table** sorted by the blended **AI Reporter Model Score** (ML + CVSS + Nessus severity)
- 🤖 **AI Remediation Assistant** with executive summary bullets and terminal/CLI fix recommendations
- 📄 **One-click PDF export** with embedded charts, top findings, and remediation steps
- 🔐 **No API keys required** — ships with built-in synthetic training data

---

## 🧱 Project Structure

```
ai_reporter/
├── app.py              # Streamlit dashboard (entry point)
├── parser.py           # Nessus .nessus / .xml / .csv parser
├── model.py            # TF-IDF + Random Forest triage engine
├── report_gen.py       # PDF executive report generator
├── requirements.txt    # Python dependencies
└── README.md
```

---

## 🛠️ Technical Stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| Frontend / Dashboard | Streamlit |
| Data Handling | Pandas, NumPy, `xml.etree.ElementTree` |
| ML / NLP | Scikit-learn (TF-IDF + Random Forest) |
| Visualization | Plotly, Matplotlib |
| PDF Generation | FPDF2 |

---

## 🚀 Installation

### 1. Clone or create the project folder

```bash
mkdir ai_reporter
cd ai_reporter
```

Place the following files in this folder:

```
app.py
parser.py
model.py
report_gen.py
requirements.txt
```

### 2. Create a virtual environment

**Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell):**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the app

```bash
streamlit run app.py
```

Then open **http://localhost:8501** in your browser.

> **First-run note:** Streamlit asks for an email once. Just press **Enter** to skip.
> To skip permanently, set:
> ```bash
> export STREAMLIT_BROWSER_GATHER_USAGE_STATS=false   # Linux/macOS
> ```
> ```powershell
> $env:STREAMLIT_BROWSER_GATHER_USAGE_STATS="false"   # Windows
> ```

---

## 📦 `requirements.txt`

```txt
streamlit>=1.32
pandas>=2.0
numpy>=1.24
scikit-learn>=1.3
plotly>=5.18
matplotlib>=3.8
fpdf2>=2.7.0,<2.9.0
beautifulsoup4>=4.12
```

---

## 🧪 Sample Test Files

You can validate the app with three small, equivalent test reports (same findings in all three formats):

| File | Format | Purpose |
|---|---|---|
| `sample.nessus` | Nessus XML | Tests the primary XML parse path |
| `sample.xml` | XML | Tests the alternate `.xml` extension route |
| `sample.csv` | CSV | Tests the CSV alias-matching parser |

### Expected results

| Metric | Value |
|---|---|
| Total Findings | 11 |
| Critical / High | 6 |
| Unique Hosts | 3 |
| P1 (Immediate) | 3 |
| P2 (Scheduled) | 3 |
| P3 (Informational) | 5 |

**Hosts covered:**
- `10.0.0.5` — `web01.corp.local`
- `10.0.0.12` — `db01.corp.local`
- `10.0.0.20` — `win-app01.corp.local`

**Findings include:** Log4Shell (CVE-2021-44228), SMBv1 / EternalBlue (CVE-2017-0144), MySQL default credentials (CVE-2012-2122), OpenSSH < 8.8 (CVE-2021-41617), RDP weak encryption, HTTP security headers missing, and informational plugins.

---

## 🖥️ How to Use

1. **Upload** a `.nessus`, `.xml`, or `.csv` report from the sidebar.
2. View the **KPI row** (Total / Critical-High / Unique Hosts / P1).
3. Inspect **interactive charts** for severity, host, and AI priority distribution.
4. Use the **filters** (severity, AI priority, host search) to narrow the **Triage Data Table**.
5. Review the **AI Remediation Assistant** for executive bullets and CLI commands.
6. Click **Prepare PDF Report** → **Download PDF Report** to export.

---

## 🧠 How the AI Triage Works

### Feature Extraction
Text from `plugin_name`, `synopsis`, `description`, `solution`, and `risk_factor` is combined and vectorized with a **TF-IDF Vectorizer** (`ngram_range=(1,2)`, `max_features=5000`, English stop-words).

### Classifier
A **Random Forest Classifier** (`n_estimators=250`, `class_weight="balanced"`) predicts one of three triage labels:

| Label | Meaning |
|---|---|
| **P1** | Critical — Immediate Patch Required |
| **P2** | Scheduled Maintenance |
| **P3** | Informational / False Positive / Acceptable Risk |

### Blended AI Reporter Model Score

```
ai_score = 0.55 × ML_priority_score
         + 0.30 × (CVSS / 10 × 100)
         + 0.15 × (Nessus_severity_rank / 4 × 100)
```

Where `ML_priority_score` is a probability-weighted value using P1 = 100, P2 = 60, P3 = 20.

This ensures the top of the table is not dominated by CVSS alone — textual context (e.g. "remote code execution", "default credentials", "actively exploited") pulls truly urgent items upward.

### Training Data
The model is trained on a **built-in synthetic dataset** (15 examples per class) so it runs **immediately without API keys or external datasets**. You can replace it in `model.py` → `_synthetic_training_data()` with your own historical, labeled findings for production use.

---

## 📊 AI Reporter Model Score — Column Reference

| Column | Description |
|---|---|
| `ai_priority` | Predicted triage label (`P1` / `P2` / `P3`) |
| `ai_confidence` | Max class probability from the Random Forest (0.0–1.0) |
| `ai_score` | Blended score (0–100) combining ML + CVSS + severity |
| `ai_reason` | Human-readable justification string |

---

## 📄 PDF Report Contents

- **Title page** with executive summary bullets
- **Severity Distribution** pie chart
- **Top Vulnerable Hosts** bar chart
- **AI Triage Priority** bar chart
- **Top N triaged findings** (default 20) with:
  - AI priority + score + confidence
  - CVSS, severity, CVE
  - Recommended solution text

---

## 🔧 Troubleshooting

### `fpdf.errors.FPDFException: Not enough horizontal space to render a single character`

This occurs with `fpdf2 >= 2.8` when `multi_cell(0, ...)` is called with the cursor at the right margin or when the text is empty.

**Fix:** Already handled in `report_gen.py` via:

- `_safe_multi_cell()` which sets `pdf.set_x(pdf.l_margin)` and always uses `w=pdf.epw`
- `_sanitize()` which never returns an empty string (falls back to `" "`)
- `requirements.txt` pins `fpdf2>=2.7.0,<2.9.0`

If you still see it, verify your installed version:

```bash
pip show fpdf2
pip install "fpdf2>=2.7.0,<2.9.0" --upgrade
```

### Streamlit asks for an email on first run
Press **Enter** to skip, or set `STREAMLIT_BROWSER_GATHER_USAGE_STATS=false`.

### Empty dashboard after upload
- Check the file is a genuine Nessus export (not a summary PDF renamed to `.csv`).
- For CSV, verify columns such as `Plugin ID`, `Risk`, `Host`, `CVSS v3.0 Base Score` exist — the parser uses case-insensitive alias matching.

---

## 🗺️ Roadmap

- [ ] Persist trained model with `joblib`
- [ ] Optional Hugging Face / Ollama summarization backend
- [ ] Multi-scan diffing (compare two Nessus reports)
- [ ] Asset criticality weighting (CMDB integration)
- [ ] SARIF / JIRA ticket export
- [ ] Role-based access and scan history database

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/foo`)
3. Commit your changes
4. Push and open a Pull Request

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing and internal remediation workflows only**. Always ensure you have explicit permission to scan and process vulnerability data for the systems you analyze. The AI triage output is **advisory** and should be reviewed by a qualified security engineer before automated action is taken.

---

## 📜 License

MIT License — see `LICENSE` for details.

---

## 🙏 Acknowledgements

Built with [Streamlit](https://streamlit.io), [Scikit-learn](https://scikit-learn.org), [Pandas](https://pandas.pydata.org), [Plotly](https://plotly.com/python/), and [FPDF2](https://py-pdf.github.io/fpdf2/).
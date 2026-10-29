# National Cyber Threat Intelligence & Risk Analytics Platform (NCTIRAP)

> **Academic Capstone Project — B.Tech Computer Science | Software Engineering**  
> ⚠️ **Academic Disclaimer**: This software is an academic prototype developed solely for educational and demonstration purposes. It does **not** perform real-time monitoring, does **not** connect to any government, classified, or restricted networks, and does **not** represent official Indian national security or statutory policy (e.g., CERT-In or NCIIPC mandates). All outputs and risk scores carry the explicit label:  
> **"Academic Model — Not an Official Government Metric."**

---

## 1. Project Overview

The **National Cyber Threat Intelligence & Risk Analytics Platform (NCTIRAP)** analyzes historical cybersecurity incident intelligence and known software vulnerabilities to assess and quantify cyber risk across India's critical infrastructure sectors (Power & Energy, Banking & Finance, Telecommunications, Government Services, Healthcare, Transportation, and Public Defence Data).

The platform bridges threat intelligence data with explainable quantitative risk scoring, storing validated records in a local SQLite relational database and generating structured analytical data models for interactive **Microsoft Power BI** executive dashboards.

---

## 2. Key Features

1. **Automated & Validated Data Ingestion**:
   - Ingests public cybersecurity intelligence from NIST NVD (CVEs) and CISA KEV (Known Exploited Vulnerabilities catalog).
   - Ingests statistically calibrated historical incident data modeled on published CERT-In Annual Report distributions (2021–2024).
   - Validates mandatory schemas, data types, and timestamps without altering raw source files.

2. **Non-Destructive Data Cleaning & Standardization**:
   - Removes duplicate incident records via natural business keys (`incident_id`).
   - Normalizes dates into ISO 8601 (`YYYY-MM-DD`).
   - Maps messy categories to controlled taxonomies defined in [`config/taxonomy.json`](file:///c:/Users/rajla/Downloads/A%20-%20DAV/CyberSentinel/config/taxonomy.json).
   - Generates audit reports (`output/reports/preprocessing_summary.csv`).

3. **Historical Cybersecurity Analytics Engine**:
   - Computes attack type frequency distributions and Pareto cumulative percentages.
   - Computes severity profiles across Critical, High, Medium, and Low tiers.
   - Calculates annual and monthly temporal trends with Year-over-Year (YoY) percentage changes.
   - Evaluates multi-sector cross-tabulations and annual sector targeting shifts.
   - Calculates CVSS descriptive statistics (Mean, Median, Standard Deviation, Interquartile Range).

4. **Explainable Academic Cyber Risk Scoring Model**:
   - Computes the **Academic Cyber Risk Score (ACRS)** per critical sector using the three approved normalized components:
     $$\text{ACRS}_s = 0.40 \cdot \text{NIFS}_s + 0.40 \cdot \text{WSS}_s + 0.20 \cdot \text{NSCS}_s \in [0, 100]$$
   - Computes the **National Cyber Risk Index (NCRI)** as a weighted national indicator:
     $$\text{NCRI} = \sum_{s} \text{SCW}_s \times \text{ACRS}_s \in [0, 100]$$
   - Generates plain-language factor contribution strings explaining *why* each sector scored as it did.
   - Classifies scores deterministically into four approved risk categories: *Critical Risk (75–100)*, *High Risk (50–74)*, *Moderate Risk (25–49)*, and *Low Risk (0–24)*.

5. **Serverless Relational Storage (SQLite)**:
   - Zero-configuration local database at `database/nctirap.db`.
   - Strict primary keys, foreign keys (`PRAGMA foreign_keys = ON;`), and `CHECK` domain constraints.
   - Idempotent data ingestion preventing accidental duplicate imports.

6. **Power BI Dashboard Integration**:
   - Exports 16 clean, UTF-8 encoded analytical CSVs to `output/analytics/`.
   - Atomic writing (`safe_write_csv`) prevents partial file corruption.
   - One-click refresh workflow in Power BI Desktop.

---

## 3. Technology Stack

| Component | Technology | Rationale / Purpose |
|---|---|---|
| **Programming Language** | Python 3.10+ (Tested on 3.14) | Core programming language for data ingestion, cleaning, analytics, and risk scoring. |
| **Data Processing** | Pandas (3.0+), NumPy (2.0+) | High-performance tabular data manipulation, statistical aggregations, and vectorized formula scoring. |
| **Relational Database** | SQLite 3 (Python stdlib `sqlite3`) | Lightweight, zero-configuration, single-file relational storage with full SQL foreign key enforcement. |
| **Data Presentation** | Microsoft Power BI Desktop | Primary user interface for interactive executive dashboards, risk gauges, and sector drilldowns. |
| **Configuration** | JSON (`config/taxonomy.json`) | Centralized controlled vocabulary and weighting parameters editable without modifying code. |
| **HTTP Ingestion** | Requests (2.31+) | Automated collection of public CISA KEV and NIST NVD datasets (`src/collect_data.py`). |
| **Testing** | Standalone Test Runners / Pytest | Complete test coverage (215 checks across 5 test suites) with zero external test runners required. |

---

## 4. Folder Structure

```
CyberSentinel/
│
├── README.md                           ← Project master documentation and evaluation guide.
├── requirements.txt                    ← Minimal Python dependencies (pandas, numpy, openpyxl, requests).
├── main.py                             ← Main orchestration pipeline script.
│
├── config/
│   └── taxonomy.json                   ← Controlled vocabularies, severity weights, and sector SCW weights.
│
├── data/
│   ├── raw/                            ← Downloaded public datasets (cisa_kev.csv, nvd_cve.csv).
│   ├── processed/                      ← Cleaned datasets (incidents_cleaned.csv, nvd_cleaned.csv, kev_cleaned.csv).
│   └── synthetic/                      ← Calibrated baseline incidents (synthetic_india_incidents.csv).
│
├── database/
│   ├── schema.sql                      ← Relational DDL script (tables, views, indexes, seed lookups).
│   └── nctirap.db                      ← SQLite database file (created and managed by the platform).
│
├── src/                                ← Core Python source modules:
│   ├── __init__.py                     ← Package initialization.
│   ├── ingestion.py                    ← Step 1: Validates and loads incident CSVs.
│   ├── cleaning.py                     ← Step 2: Cleans, deduplicates, and standardizes records.
│   ├── database.py                     ← Step 3: SQLite connection, insertion, and query utilities.
│   ├── init_database.py                ← Standalone tool: Initialises schema and seeds lookup tables.
│   ├── import_processed_data.py        ← Standalone tool: Ingests processed CSVs into SQLite tables.
│   ├── analytics.py                    ← Step 4: Computes historical trends, distributions, and CVSS stats.
│   ├── risk_scoring.py                 ← Step 5: Computes ACRS, NCRI, ATRS, and factor explanations.
│   ├── export.py                       ← Step 6: Atomic safe CSV export to output/analytics/.
│   ├── collect_data.py                 ← Data collection utility for NVD API and CISA KEV feeds.
│   └── inspect_datasets.py             ← Data inspection and profiling utility.
│
├── output/
│   ├── analytics/                      ← ⭐ POWER BI DATA SOURCE FOLDER (16 CSV tables).
│   │   ├── sector_risk_scores.csv      ← Sector ACRS scores, factor contributions, and rankings.
│   │   ├── national_risk_index.csv     ← NCRI composite score (54.35) and period metadata.
│   │   ├── threat_risk_scores.csv      ← Dual-perspective threat category risk rankings.
│   │   ├── threat_distribution.csv     ← Incident counts and percentages by attack type.
│   │   ├── severity_distribution.csv   ← Severity breakdown (Critical, High, Medium, Low).
│   │   ├── incident_trends_annual.csv  ← Annual trend time-series with YoY percentage growth.
│   │   ├── incident_trends_monthly.csv ← Monthly time-series across 48 months (2021–2024).
│   │   ├── sector_comparison.csv       ← Sector incident volume and primary threat vectors.
│   │   ├── sector_severity_breakdown.csv ← Sector-by-severity cross-tabulation matrix.
│   │   ├── vulnerability_cvss_statistics.csv ← CVSS descriptive statistics (Mean, Median, IQR).
│   │   ├── vulnerability_kev_summary.csv ← CISA KEV exploitation and ransomware usage summary.
│   │   └── descriptive_statistics_metadata.csv ← Complete governance and coverage log.
│   └── reports/
│       └── preprocessing_summary.csv   ← Data cleaning and retention quality audit.
│
├── logs/
│   ├── run_log.txt                     ← Complete pipeline execution log with timestamps.
│   └── import_log.txt                  ← Audit trail of imported files and row counts.
│
└── tests/                              ← Test suites (215 automated checks):
    ├── test_environment.py             ← Checks Python version and library availability (19 checks).
    ├── test_data_collection.py         ← Validates public downloads and parser logic (33 checks).
    ├── test_database.py                ← Tests SQLite schema, constraints, deduplication, joins (41 checks).
    ├── test_analytics.py               ← Tests grouping, trends, YoY math, and statistics (47 checks).
    └── test_risk_scoring.py            ← Tests ACRS/NCRI formulas, boundary values, NaN handling (75 checks).
```

---

## 5. Dataset Sources & Limitations

| Dataset Name | Source Organization | Record Count | Real / Synthetic | Purpose & Methodological Limitations |
|---|---|:---:|:---:|---|
| **Historical Cyber Incidents** | Statistical baseline calibrated against CERT-In Annual Reports | 2,434 rows | **SYNTHETIC** | Models incident distributions (phishing, ransomware, breach) and sector impacts reported in Indian Computer Emergency Response Team (CERT-In) public annual reviews (2021–2024). *Limitation: Synthetic proxy data; does not represent classified or real-time government telemetry.* |
| **National Vulnerability Database (NVD)** | NIST, U.S. Department of Commerce | 7,861 rows | **PUBLIC** | Disclosed Common Vulnerabilities and Exposures (CVEs) conforming to CVSS v3.x standards with vendor/product mappings and CWE classifications. |
| **Known Exploited Vulnerabilities (KEV)** | CISA, U.S. Department of Homeland Security | 1,234 rows | **PUBLIC** | Authoritative catalog of software vulnerabilities actively weaponized in the wild by threat actors, cross-referenced with ransomware campaign telemetry. |

---

## 6. Step-by-Step Setup & Installation Guide

### Step 1 — Check Python Installation
Open a terminal (PowerShell on Windows) and run:
```powershell
python --version
```
Ensure you have **Python 3.10 or later**.

### Step 2 — Navigate to the Project Root
```powershell
cd "C:\Users\rajla\Downloads\A - DAV\CyberSentinel"
```

### Step 3 — Install Required Libraries
```powershell
pip install -r requirements.txt
```
*(Dependencies installed: `pandas`, `numpy`, `openpyxl`, `requests`).*

### Step 4 — Run the Environment Pre-Check
```powershell
python tests/test_environment.py
```
*Expected: 19/19 checks passed.*

---

## 7. How to Run the Platform

You can execute the platform using either the end-to-end pipeline runner or individual modular scripts:

### Method A — Run the Full End-to-End Pipeline (Recommended)
Executes data validation, cleaning, SQLite database loading, analytics computation, risk scoring, and CSV export in a single command:
```powershell
python main.py --input data/processed/incidents_cleaned.csv
```
*Execution time: ~0.4 to 0.6 seconds.*

---

### Method B — Run Individual Modular Scripts

#### 1. Initialise the SQLite Database
Creates the database schema at `database/nctirap.db` with all 9 tables, views, and seed lookup data:
```powershell
python src/init_database.py
```
*(To wipe and rebuild cleanly from scratch, add `--recreate`: `python src/init_database.py --recreate`).*

#### 2. Ingest Processed Data into SQLite
Ingests cleaned incidents and vulnerabilities, enriches them with CISA KEV exploitation flags, and performs duplicate prevention:
```powershell
python src/import_processed_data.py
```

#### 3. Run Historical Analytics
Calculates attack type distributions, monthly/annual trends, sector comparisons, and CVSS statistics:
```powershell
python -m src.analytics
```

#### 4. Run Explainable Cyber Risk Scoring
Computes sector ACRS scores, national NCRI index, and threat risk scores, outputting an explainable console report:
```powershell
# Run with normalized recommended formula [0, 100]:
python -m src.risk_scoring

# Run with literal SRS Section 8.4 formula (capped at 84.0):
python -m src.risk_scoring --literal-srs
```

#### 5. Inspect Cleaned Datasets
Displays column names, missing values, data types, and first 5 rows:
```powershell
python -m src.inspect_datasets
```

---

## 8. Interactive Web Dashboard (FE-001 SOC Interface)

A complete, high-performance web dashboard inspired by modern Security Operations Center (SOC) platforms has been implemented directly in the project. It provides instant browser-based visualization of all analytical models, SQLite relational data, and threat intelligence feeds.

### Features
* **Dark Navy SOC Theme**: High-contrast dark theme with cyan/blue accents, severity badges, and responsive card layouts.
* **5 Interactive Themed Views**:
  1. **National Cyber Overview**: NCRI gauge indicator (54.35 — High Risk), KPI metrics, monthly incident trajectory line chart (2021–2024), threat category donut chart, sector rankings, and recent notable incident records.
  2. **Critical Infrastructure**: Sector risk rankings (ACRS), factor breakdown stacked bar chart (Frequency, Severity, Criticality), and ranked sector scoreboard table with category/search filters.
  3. **Threat Intelligence**: Attack vector distributions, severity breakdown charts, and searchable/filterable paginated incident table.
  4. **Vulnerability Intelligence**: Monitored CVEs (7,861), CVSS score distribution histogram, CISA KEV active exploitation metrics (1,756 exploited, 361 ransomware weaponized), and searchable CVE table.
  5. **Risk Analysis**: Quantitative risk formulation explainer, severity-versus-frequency scatter matrix (NIFS vs WSS), and threat risk ranking model.
* **REST API Endpoints**: Modular Flask backend serving `/api/overview`, `/api/sectors`, `/api/threats`, `/api/vulnerabilities`, `/api/vulnerabilities/list`, `/api/incidents/list`, `/api/risk-analysis`, and `/api/system-status`.
* **Zero Cloud Lock-in**: Powered by local SQLite (`database/nctirap.db`), local analytics CSVs, and bundled local Chart.js.

### How to Launch the Web Dashboard
From the `CyberSentinel/` directory in Windows PowerShell, run:
```powershell
.\venv\Scripts\python.exe app.py
```
*(Or `python app.py` if your virtual environment is activated).*

### Open in Browser
Navigate to:
```text
http://127.0.0.1:5000
```

### How to Stop the Server
In the PowerShell terminal running `app.py`, press:
```text
Ctrl + C
```

---

## 9. Power BI Dashboard Setup & Refresh Guide

Microsoft Power BI Desktop is the primary interactive user interface for the platform.

### Step 1 — Connect Power BI Desktop to the Analytical CSVs
1. Open **Microsoft Power BI Desktop**.
2. Click **Home &rarr; Get Data &rarr; Text/CSV**.
3. Browse to `CyberSentinel/output/analytics/` and load:
   - `national_risk_index.csv`
   - `sector_risk_scores.csv`
   - `severity_distribution.csv`
   - `incident_trends_annual.csv`
   - `threat_distribution.csv`
   - `descriptive_statistics_metadata.csv`

### Step 2 — Constructing Dashboard Pages

#### Page 1: National Cyber Overview
- **Title Banner**: NCTIRAP Overview with explicit label: *"Academic Model — Not an Official Government Metric."*
- **KPI Card 1**: Total Incidents Monitored &rarr; `severity_distribution[incident_count]` (`2,434`).
- **KPI Card 2**: Critical Severity Incidents &rarr; Filter where `severity = "Critical"` (`235`, `9.65%`).
- **National Risk Gauge**: `national_risk_index[ncri_score]` (`54.35 / 100.00` &rarr; **HIGH RISK**), Min: `0`, Max: `100`, Target: `75`.
- **Trend Line Chart**: X-axis = `incident_trends_annual[year]`, Y-axis = `incident_count` (shows annual growth from `493` in 2021 to `770` in 2024).
- **Attack Type Bar Chart**: Y-axis = `threat_type`, X-axis = `incident_count` (Phishing `666`, Malware `519`, Ransomware `282`, Data Breach `263`, Other `704`).
- **Metadata Table**: Displays temporal coverage (`2021–2024`) and non-causation policy statement.

#### Page 2: Critical Infrastructure Analysis
- **Sector Comparison Bar Chart**: Compares incident volumes across 8 sectors (Government Services `624`, Banking & Finance `522`, Telecom `349`, etc.).
- **Sector Risk Ranking Matrix**: Table showing `rank`, `sector_name`, `acrs_score`, `risk_category`, and `contributing_factors`.
- **Factor Explainability Chart**: Stacked bar chart showing relative contribution points of Frequency ($\alpha \cdot \text{NIFS}$), Severity ($\beta \cdot \text{WSS}$), and Criticality ($\gamma \cdot \text{NSCS}$).

#### Page 3: Risk Analysis
- **ACRS Distribution Visual**: Sectors color-coded by category (*Critical*, *High*, *Moderate*, *Low*).
- **Severity vs. Frequency Scatter Plot**: X-axis = `nifs_score` (Frequency), Y-axis = `wss_score` (Severity), Bubble Size = `scw` (Criticality Weight).
- **Interactive Slicers**: Slicers for `year`, `sector_name`, `severity`, and `threat_type`.

### Step 3 — How to Refresh the Dashboard
When new data is added or when `python main.py` is re-run:
1. In Power BI Desktop, navigate to the **Home** tab on the top ribbon.
2. Click the **Refresh** button (or press `F5`).
3. Power BI re-reads all CSV files and updates all visuals within 2–3 seconds.

---

## 10. Automated Testing Suite

The project includes six independent test suites covering 224 automated assertions.

Run all test suites from PowerShell:
```powershell
# 1. Environment & Dependencies (19 checks)
python tests/test_environment.py

# 2. Public Data Collection & Parsers (33 checks)
python tests/test_data_collection.py

# 3. SQLite Database, Constraints & Deduplication (41 checks)
python tests/test_database.py

# 4. Historical Analytics, Trends & CVSS Statistics (47 checks)
python tests/test_analytics.py

# 5. Risk Scoring Formulas, Boundaries & Missing Data (75 checks)
python tests/test_risk_scoring.py

# 6. Web Dashboard & REST API Endpoints (9 checks)
python tests/test_web_dashboard.py
```

*All 224 checks pass with 100% success (0 failed, 0 skipped).*

---

## 11. Known Limitations & Future Improvements

### Academic Limitations
1. **Synthetic Incident Baseline**: Public Indian cybersecurity telemetry is aggregated and redacted at the national level. The 2,434 incident records are statistically calibrated synthetic proxies based on CERT-In Annual Report proportions. They provide structural realism for academic evaluation but do not represent classified government incidents.
2. **Static Risk Weights**: Sector Criticality Weights ($\text{SCW}$) and formula coefficients ($\alpha=0.40, \beta=0.40, \gamma=0.20$) are fixed academic values based on critical infrastructure dependency research, rather than empirically optimized regression models.
3. **No Real-Time Telemetry**: The system operates strictly as an offline batch intelligence platform. It does not monitor live network packets or trigger real-time SIEM alerts.

### Future Improvements
1. **Longitudinal NCRI Tracking**: Calculate quarterly rolling NCRI time-series as additional annual datasets become available.
2. **Client-Server RDBMS Migration**: Transition the SQLite database layer to enterprise PostgreSQL using SQLAlchemy or connection pooling.
3. **Automated PDF Executive Briefing Generation**: Add automated PDF export using ReportLab or WeasyPrint alongside the Power BI dashboards.

---

*Project: National Cyber Threat Intelligence & Risk Analytics Platform (NCTIRAP)*  
*Academic Year: 2026 | Course: B.Tech Computer Science — Software Engineering Capstone*

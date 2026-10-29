"""
src/inspect_datasets.py — Dataset Inspection Script
=====================================================
National Cyber Threat Intelligence & Risk Analytics Platform

PURPOSE:
    This script loads each raw dataset, displays a structured report,
    and saves a copy of the cleaned data to data/processed/.

    It is the first thing you run after downloading the datasets.
    It tells you EXACTLY what is in each file before any analysis begins.

HOW TO RUN (from the CyberSentinel/ folder):
    Step 1 — Activate your virtual environment:
        Windows:  venv\\Scripts\\activate
        macOS/Linux: source venv/bin/activate

    Step 2 — Run this script:
        python -m src.inspect_datasets

    Step 3 — Read the output in the terminal and check the files saved to:
        data/processed/   — cleaned versions of each dataset
        output/reports/   — inspection report CSVs for each dataset

WHAT THIS SCRIPT PRODUCES:
    For each dataset, it prints to the terminal:
        [A] Dataset identification (name, source, label)
        [B] First 5 rows (preview)
        [C] Column names and data types
        [D] Total record count
        [E] Missing value count per column
        [F] Duplicate record count
        [G] Key distribution summary (top values per important column)

    It also saves:
        data/processed/incidents_cleaned.csv    — cleaned synthetic incidents
        data/processed/kev_cleaned.csv          — cleaned CISA KEV records
        data/processed/nvd_cleaned.csv          — cleaned NVD CVE records
        output/reports/inspection_report.csv    — combined machine-readable report

DATASETS INSPECTED:
    1. CISA KEV Catalog         → data/raw/cisa_kev.csv         (PUBLIC)
    2. NVD CVE Records          → data/raw/nvd_cve.csv          (PUBLIC)
    3. India Synthetic Incidents → data/synthetic/synthetic_india_incidents.csv (SYNTHETIC)

SRS REFERENCES:
    FR-001, FR-002, FR-003, FR-005, FR-006, FR-007, FR-008, FR-009, FR-010,
    FR-011, FR-012, NFR-004, NFR-007
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd
import numpy as np

# =============================================================================
# PATH SETUP
# =============================================================================

PROJECT_ROOT  = Path(__file__).resolve().parent.parent
RAW_DIR       = PROJECT_ROOT / "data" / "raw"
SYNTHETIC_DIR = PROJECT_ROOT / "data" / "synthetic"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
REPORTS_DIR   = PROJECT_ROOT / "output" / "reports"
LOG_DIR       = PROJECT_ROOT / "logs"
TAXONOMY_PATH = PROJECT_ROOT / "config" / "taxonomy.json"
SCHEMA_PATH   = PROJECT_ROOT / "database" / "schema.sql"
DB_PATH       = PROJECT_ROOT / "database" / "nctirap.db"

# Add project root to path so we can import src modules
sys.path.insert(0, str(PROJECT_ROOT))

from src.ingestion import load_incident_csv, load_cve_csv, validate_columns, log_import
from src.cleaning  import (
    clean_incident_data, clean_cve_data,
    save_cleaning_report,
)
from src.database  import get_connection, initialise_database, insert_incidents, insert_cve_records


# =============================================================================
# LOGGING SETUP
# =============================================================================

def _setup_logging() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / "inspection.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file, encoding="utf-8"),
        ],
        force=True,
    )


# =============================================================================
# PRINTING HELPERS
# =============================================================================

DIVIDER_MAJOR = "=" * 70
DIVIDER_MINOR = "-" * 70


def _header(title: str) -> None:
    print()
    print(DIVIDER_MAJOR)
    print(f"  {title}")
    print(DIVIDER_MAJOR)


def _section(label: str) -> None:
    print()
    print(f"  [{label}]")
    print(DIVIDER_MINOR)


def _print_dataset_report(
    name: str,
    source_url: str,
    data_label: str,        # "PUBLIC" or "SYNTHETIC"
    limitation: str,
    df: pd.DataFrame,
    key_columns: list,
) -> dict:
    """
    Print a complete inspection report for one DataFrame.

    Prints sections A–G to the terminal and returns a dict summarising
    the dataset's metrics (used later for the combined report CSV).

    Args:
        name        : Human-readable name of the dataset.
        source_url  : Official URL where the data comes from.
        data_label  : "PUBLIC" (real data) or "SYNTHETIC" (generated).
        limitation  : One-sentence description of data limitations.
        df          : The loaded (raw) DataFrame.
        key_columns : Which columns to show distribution summaries for.

    Returns:
        dict: Summary metrics for this dataset.
    """
    _header(name)

    # ── [A] Identification ────────────────────────────────────────────────────
    _section("A  Dataset Identification")
    print(f"  Name         : {name}")
    print(f"  Source       : {source_url}")
    print(f"  Data Label   : {data_label}")
    print(f"  Inspected At : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Limitation   : {limitation}")

    if df.empty:
        print("  [WARNING] DataFrame is EMPTY — no records to inspect.")
        return {"dataset": name, "rows": 0, "columns": 0, "status": "EMPTY"}

    # ── [B] First 5 rows ──────────────────────────────────────────────────────
    _section("B  First 5 Rows (Preview)")
    # Truncate long text cells for readability
    preview_df = df.head(5).copy()
    for col in preview_df.select_dtypes(include="str").columns:
        preview_df[col] = preview_df[col].astype(str).str[:60]

    # Print with wrapping-friendly options
    pd.set_option("display.max_columns", 6)
    pd.set_option("display.width", 120)
    pd.set_option("display.max_colwidth", 58)
    print(preview_df.to_string(index=True))
    pd.reset_option("display.max_columns")
    pd.reset_option("display.width")
    pd.reset_option("display.max_colwidth")

    # ── [C] Column names and data types ───────────────────────────────────────
    _section("C  Column Names and Data Types")
    dtype_df = pd.DataFrame({
        "column"   : df.columns,
        "dtype"    : [str(df[c].dtype) for c in df.columns],
        "example"  : [str(df[c].iloc[0])[:50] if len(df) > 0 else "" for c in df.columns],
    })
    print(dtype_df.to_string(index=False))

    # ── [D] Record count ──────────────────────────────────────────────────────
    _section("D  Record Count")
    print(f"  Total rows    : {len(df):,}")
    print(f"  Total columns : {len(df.columns)}")

    # ── [E] Missing values ────────────────────────────────────────────────────
    _section("E  Missing Values per Column")
    missing = df.isnull().sum()
    missing_pct = (missing / len(df) * 100).round(2)
    missing_df = pd.DataFrame({
        "column"      : missing.index,
        "missing_count": missing.values,
        "missing_pct"  : missing_pct.values,
    })
    missing_df = missing_df[missing_df["missing_count"] > 0]
    if missing_df.empty:
        print("  No missing values in any column.")
    else:
        print(missing_df.to_string(index=False))

    # ── [F] Duplicate records ─────────────────────────────────────────────────
    _section("F  Duplicate Records")
    dup_count = int(df.duplicated().sum())
    print(f"  Exact duplicate rows (all columns identical) : {dup_count:,}")

    # For incident data, also check the composite key duplicates
    composite_key = ["incident_date", "threat_type", "target_sector"]
    composite_existing = [c for c in composite_key if c in df.columns]
    if len(composite_existing) == 3:
        composite_dups = int(df.duplicated(subset=composite_existing).sum())
        print(
            f"  Composite key duplicates "
            f"(date + threat_type + sector) : {composite_dups:,}"
        )

    # For CVE data, check cve_id duplicates
    if "cve_id" in df.columns:
        cve_dups = int(df.duplicated(subset=["cve_id"]).sum())
        print(f"  Duplicate cve_id values : {cve_dups:,}")

    # ── [G] Key distributions ─────────────────────────────────────────────────
    _section("G  Key Column Distributions (Top 10 Values)")
    for col in key_columns:
        if col not in df.columns:
            print(f"  Column '{col}' not found in this dataset.")
            continue
        dist = df[col].value_counts().head(10)
        pct  = (dist / len(df) * 100).round(1)
        dist_df = pd.DataFrame({"value": dist.index, "count": dist.values, "pct%": pct.values})
        print(f"\n  {col}:")
        print(dist_df.to_string(index=False))

    # ── Summary metrics dict ──────────────────────────────────────────────────
    return {
        "dataset"          : name,
        "data_label"       : data_label,
        "rows"             : len(df),
        "columns"          : len(df.columns),
        "missing_cells"    : int(df.isnull().sum().sum()),
        "exact_duplicates" : dup_count,
        "source_url"       : source_url,
        "inspected_at"     : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status"           : "OK",
    }


# =============================================================================
# LOAD TAXONOMY
# =============================================================================

def _load_taxonomy() -> dict:
    if not TAXONOMY_PATH.exists():
        logging.error(f"taxonomy.json not found at {TAXONOMY_PATH}")
        sys.exit(1)
    with open(TAXONOMY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


# =============================================================================
# DATASET 1 — CISA KNOWN EXPLOITED VULNERABILITIES
# =============================================================================

def inspect_cisa_kev(taxonomy: dict, report_rows: list) -> pd.DataFrame:
    """
    Load, inspect, and clean the CISA KEV catalog.

    Returns the cleaned DataFrame (or empty DataFrame on failure).
    """
    kev_path = RAW_DIR / "cisa_kev.csv"

    print()
    print(DIVIDER_MAJOR)
    print("  DATASET 1: CISA Known Exploited Vulnerabilities (KEV)")
    print(DIVIDER_MAJOR)

    if not kev_path.exists():
        print()
        print("  [NOT FOUND] cisa_kev.csv does not exist.")
        print()
        print("  HOW TO DOWNLOAD:")
        print("    Run: python -m src.collect_data --skip-nvd --skip-synthetic")
        print()
        print("  OR download manually from:")
        print("    https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
        print("    Click 'Download CSV' and save the file to:")
        print(f"    {kev_path}")
        return pd.DataFrame()

    # Load
    mandatory = ["cve_id", "published_date"]
    try:
        raw_df = load_cve_csv(kev_path, mandatory)
    except Exception as exc:
        logging.error(f"Failed to load KEV: {exc}")
        return pd.DataFrame()

    # Print inspection report
    metrics = _print_dataset_report(
        name        = "CISA Known Exploited Vulnerabilities (KEV)",
        source_url  = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        data_label  = "PUBLIC — Real U.S. government data (CISA)",
        limitation  = (
            "Covers only vulnerabilities confirmed as actively exploited in the wild "
            "by U.S. CISA. It does not cover all CVEs — only those prioritised for "
            "patching. The full NVD has broader coverage. KEV does not include "
            "India-specific targeting information."
        ),
        df          = raw_df,
        key_columns = ["cvss_severity", "known_ransomware_use"],
    )
    report_rows.append(metrics)

    # Clean
    print()
    print("  Cleaning KEV data...")
    cleaned_df, clean_report = clean_cve_data(raw_df)

    # Save cleaned version
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    out_path = PROCESSED_DIR / "kev_cleaned.csv"
    cleaned_df.to_csv(out_path, index=False, encoding="utf-8")
    print(f"  Cleaned file saved to: {out_path}")

    # Save cleaning report
    save_cleaning_report(clean_report, REPORTS_DIR / "kev")

    return cleaned_df


# =============================================================================
# DATASET 2 — NVD CVE RECORDS
# =============================================================================

def inspect_nvd_cve(taxonomy: dict, report_rows: list) -> pd.DataFrame:
    """
    Load, inspect, and clean the NVD CVE dataset.

    Returns the cleaned DataFrame (or empty DataFrame on failure).
    """
    nvd_path = RAW_DIR / "nvd_cve.csv"

    print()
    print(DIVIDER_MAJOR)
    print("  DATASET 2: NIST National Vulnerability Database — CVE Records")
    print(DIVIDER_MAJOR)

    if not nvd_path.exists():
        print()
        print("  [NOT FOUND] nvd_cve.csv does not exist.")
        print()
        print("  HOW TO DOWNLOAD:")
        print("    Run: python -m src.collect_data --skip-kev --skip-synthetic")
        print()
        print("  OR visit:")
        print("    https://nvd.nist.gov/developers/vulnerabilities")
        print(f"  Save the output as: {nvd_path}")
        return pd.DataFrame()

    mandatory = taxonomy.get("mandatory_cve_columns", ["cve_id", "published_date"])
    try:
        raw_df = load_cve_csv(nvd_path, mandatory)
    except Exception as exc:
        logging.error(f"Failed to load NVD: {exc}")
        return pd.DataFrame()

    metrics = _print_dataset_report(
        name        = "NIST NVD CVE Records (API 2.0 export)",
        source_url  = "https://nvd.nist.gov/developers/vulnerabilities",
        data_label  = "PUBLIC — Real U.S. NIST data",
        limitation  = (
            "CVE data describes software vulnerabilities globally, not India-specific "
            "incidents. The NVD API imposes a 120-day date range per request; "
            "multiple requests are needed for historical coverage. CVEs without a "
            "CVSS score are marked 'Unknown'. This dataset covers only the date "
            "range requested during data collection."
        ),
        df          = raw_df,
        key_columns = ["cvss_severity", "cwe_ids"],
    )
    report_rows.append(metrics)

    print()
    print("  Cleaning NVD data...")
    cleaned_df, clean_report = clean_cve_data(raw_df)

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    out_path = PROCESSED_DIR / "nvd_cleaned.csv"
    cleaned_df.to_csv(out_path, index=False, encoding="utf-8")
    print(f"  Cleaned file saved to: {out_path}")

    save_cleaning_report(clean_report, REPORTS_DIR / "nvd")

    return cleaned_df


# =============================================================================
# DATASET 3 — INDIA SYNTHETIC INCIDENTS
# =============================================================================

def inspect_synthetic_incidents(taxonomy: dict, report_rows: list) -> pd.DataFrame:
    """
    Load, inspect, and clean the synthetic India incident dataset.

    Returns the cleaned DataFrame (or empty DataFrame on failure).
    """
    syn_path = SYNTHETIC_DIR / "synthetic_india_incidents.csv"

    print()
    print(DIVIDER_MAJOR)
    print("  DATASET 3: India Cyber Incident Synthetic Dataset")
    print(DIVIDER_MAJOR)

    # Explain WHY this is synthetic before showing the data
    print()
    print("  ** CERT-In Data Availability Limitation **")
    print("  " + "-" * 66)
    print(
        "  CERT-In (Indian Computer Emergency Response Team) does NOT publish\n"
        "  raw, machine-readable incident data (CSV or JSON). Only aggregated\n"
        "  annual statistics are available in PDF reports at cert-in.org.in.\n"
        "\n"
        "  Because individual incident records do not exist in any public format,\n"
        "  this project uses a SYNTHETIC dataset that:\n"
        "    - Is generated from CERT-In's published aggregate statistics\n"
        "      (national annual totals, sector breakdowns from official PDFs).\n"
        "    - Carries data_source = 'SYNTHETIC' on every single row.\n"
        "    - Is stored in data/synthetic/ (NEVER in data/raw/).\n"
        "    - Is used only for testing the analytics pipeline.\n"
        "    - Does NOT represent real Indian cyber incidents.\n"
        "\n"
        "  Source of aggregate statistics:\n"
        "    CERT-In Annual Reports: https://www.cert-in.org.in/\n"
        "    (Navigate to Knowledge Base > Annual Report)\n"
        "\n"
        "  Reported national totals used as basis:\n"
        "    2021: ~14.02 lakh incidents  |  2022: ~13.91 lakh incidents\n"
        "    2023: ~15.92 lakh incidents  |  2024: ~20.41 lakh incidents\n"
    )
    print("  " + "-" * 66)

    if not syn_path.exists():
        print()
        print("  [NOT FOUND] synthetic_india_incidents.csv does not exist.")
        print()
        print("  HOW TO GENERATE:")
        print("    Run: python -m src.collect_data --skip-kev --skip-nvd")
        return pd.DataFrame()

    mandatory = taxonomy.get(
        "mandatory_incident_columns",
        ["incident_id", "incident_date", "threat_type", "target_sector",
         "severity", "data_source"]
    )

    try:
        raw_df = load_incident_csv(syn_path, mandatory)
    except Exception as exc:
        logging.error(f"Failed to load synthetic incidents: {exc}")
        return pd.DataFrame()

    metrics = _print_dataset_report(
        name        = "India Cyber Incident Synthetic Dataset",
        source_url  = "SYNTHETIC — generated from CERT-In Annual Report statistics",
        data_label  = "SYNTHETIC — NOT real incident records",
        limitation  = (
            "This dataset is generated, not observed. Proportions are approximate.\n"
            "  It exists only because CERT-In does not release individual incident "
            "records publicly.\n"
            "  All records are clearly labelled data_source='SYNTHETIC'.\n"
            "  This data should NEVER be cited as evidence of real events."
        ),
        df          = raw_df,
        key_columns = ["threat_type", "target_sector", "severity", "target_state"],
    )
    report_rows.append(metrics)

    print()
    print("  Cleaning synthetic incidents...")
    cleaned_df, clean_report = clean_incident_data(raw_df, taxonomy)

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    out_path = PROCESSED_DIR / "incidents_cleaned.csv"
    cleaned_df.to_csv(out_path, index=False, encoding="utf-8")
    print(f"  Cleaned file saved to: {out_path}")

    save_cleaning_report(clean_report, REPORTS_DIR / "incidents")

    return cleaned_df


# =============================================================================
# DATABASE LOAD
# =============================================================================

def load_into_database(
    incidents_df: pd.DataFrame,
    kev_df: pd.DataFrame,
    nvd_df: pd.DataFrame,
    taxonomy: dict,
) -> None:
    """
    Initialise the SQLite database and insert all cleaned records.

    Args:
        incidents_df : Cleaned synthetic incident records.
        kev_df       : Cleaned CISA KEV CVE records.
        nvd_df       : Cleaned NVD CVE records.
        taxonomy     : Taxonomy configuration dict.
    """
    print()
    print(DIVIDER_MAJOR)
    print("  LOADING DATA INTO SQLITE DATABASE")
    print(DIVIDER_MAJOR)

    try:
        conn = get_connection(DB_PATH)
        initialise_database(conn, SCHEMA_PATH)
        print(f"  Database initialised at: {DB_PATH}")
    except Exception as exc:
        logging.error(f"  Database initialisation failed: {exc}")
        return

    # Insert synthetic incidents
    if not incidents_df.empty:
        n = insert_incidents(conn, incidents_df, taxonomy)
        print(f"  Incidents inserted : {n:,}")

    # Merge KEV + NVD into one CVE DataFrame for insertion
    cve_frames = [df for df in [kev_df, nvd_df] if not df.empty]
    if cve_frames:
        combined_cve = pd.concat(cve_frames, ignore_index=True)
        # Drop duplicate CVE IDs that appear in both KEV and NVD
        combined_cve = combined_cve.drop_duplicates(subset=["cve_id"], keep="first")
        n_cve = insert_cve_records(conn, combined_cve)
        print(f"  CVE records inserted: {n_cve:,}")
    else:
        print("  No CVE data to insert.")

    conn.close()
    print(f"  Database connection closed.")


# =============================================================================
# COMBINED REPORT
# =============================================================================

def save_combined_report(report_rows: list) -> None:
    """
    Save a combined machine-readable inspection report to CSV.

    Args:
        report_rows: List of dicts, one per dataset, from _print_dataset_report().
    """
    if not report_rows:
        return

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = REPORTS_DIR / "inspection_report.csv"
    pd.DataFrame(report_rows).to_csv(out_path, index=False, encoding="utf-8")
    print(f"\n  Combined inspection report saved to: {out_path}")


# =============================================================================
# MAIN
# =============================================================================

def main() -> None:
    _setup_logging()

    print()
    print("=" * 70)
    print("  NCTIRAP — Dataset Inspection & Initial Import")
    print(f"  Run at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    # Load taxonomy (needed for column names and controlled vocabulary)
    taxonomy = _load_taxonomy()
    print(f"\n  Taxonomy loaded from: {TAXONOMY_PATH.name}")

    # Collect summary rows for the combined report
    report_rows = []

    # Inspect each dataset
    incidents_df = inspect_synthetic_incidents(taxonomy, report_rows)
    kev_df       = inspect_cisa_kev(taxonomy, report_rows)
    nvd_df       = inspect_nvd_cve(taxonomy, report_rows)

    # Load into database
    load_into_database(incidents_df, kev_df, nvd_df, taxonomy)

    # Save combined report
    save_combined_report(report_rows)

    # Final summary
    print()
    print(DIVIDER_MAJOR)
    print("  INSPECTION SUMMARY")
    print(DIVIDER_MAJOR)
    for r in report_rows:
        label = r.get("data_label", r.get("status", ""))
        print(
            f"  {r['dataset'][:45]:<45}  "
            f"rows={r.get('rows',0):>6,}  "
            f"label={r.get('data_label','').split(' ')[0]}"
        )
    print()
    print("  Next steps:")
    print("    1. Check data/processed/ for cleaned dataset CSVs.")
    print("    2. Check output/reports/  for inspection report CSVs.")
    print("    3. Run the analytics pipeline:  python main.py")
    print()


if __name__ == "__main__":
    main()

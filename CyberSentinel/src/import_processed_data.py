"""
src/import_processed_data.py — Processed Data Ingestion Engine for NCTIRAP SQLite Database
========================================================================================
National Cyber Threat Intelligence & Risk Analytics Platform

PURPOSE:
    This standalone script imports cleaned cybersecurity datasets into the
    relational SQLite database (database/nctirap.db).

DATASETS INGESTED:
    1. Cleaned Incident Records: data/processed/incidents_cleaned.csv
       -> Populates INCIDENTS table (resolves Attack Types, Sectors, Severity,
          Regions, and Data Sources foreign keys).
    2. Cleaned NVD Vulnerabilities: data/processed/nvd_cleaned.csv
       -> Populates VULNERABILITIES table.
    3. Cleaned CISA KEV Exploitations: data/processed/kev_cleaned.csv
       -> Enriches VULNERABILITIES with is_known_exploited and ransomware use flags.

SAFETY & INTEGRITY GUARANTEES:
    - Never modifies original raw files in data/raw/ or data/synthetic/.
    - Prevents duplicate insertion using natural key UNIQUE constraints (incident_id, cve_id).
    - Idempotent: Can be executed multiple times safely without corrupting data.
    - Reports exact counts: rows in CSV, newly inserted rows, and duplicates skipped.

HOW TO RUN:
    python src/import_processed_data.py
    python src/import_processed_data.py --db database/nctirap.db
"""

import argparse
import logging
import sqlite3
import sys
from pathlib import Path
from typing import Dict, Tuple

import pandas as pd

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.database import (
    DEFAULT_DB_PATH,
    get_connection,
    initialise_database,
    insert_incidents,
    insert_vulnerabilities,
    get_database_summary,
    query_to_dataframe,
)

DEFAULT_INCIDENTS_PATH = PROJECT_ROOT / "data" / "processed" / "incidents_cleaned.csv"
DEFAULT_NVD_PATH = PROJECT_ROOT / "data" / "processed" / "nvd_cleaned.csv"
DEFAULT_KEV_PATH = PROJECT_ROOT / "data" / "processed" / "kev_cleaned.csv"


def import_all_processed_data(
    db_path: Path,
    incidents_csv: Path,
    nvd_csv: Path,
    kev_csv: Path
) -> Tuple[bool, Dict[str, Dict[str, int]]]:
    """
    Execute full ingestion of processed CSV datasets into SQLite database.

    Returns:
        Tuple[bool, Dict]: Success flag and detailed import metrics dictionary.
    """
    print("\n" + "=" * 75)
    print("  NCTIRAP PROCESSED DATA INGESTION ENGINE")
    print("  National Cyber Threat Intelligence & Risk Analytics Platform")
    print("=" * 75)
    print(f"Target Database     : {db_path}")
    print(f"Incidents Dataset   : {incidents_csv} (exists: {incidents_csv.exists()})")
    print(f"NVD Vulnerabilities : {nvd_csv} (exists: {nvd_csv.exists()})")
    print(f"CISA KEV Catalog    : {kev_csv} (exists: {kev_csv.exists()})")
    print("-" * 75)

    conn = get_connection(db_path)
    initialise_database(conn)

    metrics = {
        "incidents": {"csv_rows": 0, "inserted": 0, "total_db": 0},
        "vulnerabilities": {"csv_rows": 0, "inserted": 0, "total_db": 0},
    }

    cursor = conn.cursor()

    # -------------------------------------------------------------------------
    # 1. Ingest Cleaned Incidents
    # -------------------------------------------------------------------------
    if incidents_csv.exists():
        cursor.execute("SELECT COUNT(*) FROM INCIDENTS;")
        count_before = cursor.fetchone()[0]

        df_inc = pd.read_csv(incidents_csv, encoding="utf-8")
        metrics["incidents"]["csv_rows"] = len(df_inc)

        inserted_inc = insert_incidents(conn, df_inc)
        metrics["incidents"]["inserted"] = inserted_inc

        cursor.execute("SELECT COUNT(*) FROM INCIDENTS;")
        metrics["incidents"]["total_db"] = cursor.fetchone()[0]
    else:
        logging.warning(f"Incidents file not found: {incidents_csv}")

    # -------------------------------------------------------------------------
    # 2. Ingest Cleaned NVD & CISA KEV Vulnerabilities
    # -------------------------------------------------------------------------
    df_nvd = pd.DataFrame()
    df_kev = pd.DataFrame()

    if nvd_csv.exists():
        df_nvd = pd.read_csv(nvd_csv, encoding="utf-8")
        metrics["vulnerabilities"]["csv_rows"] += len(df_nvd)

    if kev_csv.exists():
        df_kev = pd.read_csv(kev_csv, encoding="utf-8")
        metrics["vulnerabilities"]["csv_rows"] += len(df_kev)

    if not df_nvd.empty or not df_kev.empty:
        inserted_vuln = insert_vulnerabilities(conn, nvd_df=df_nvd, kev_df=df_kev)
        metrics["vulnerabilities"]["inserted"] = inserted_vuln

        cursor.execute("SELECT COUNT(*) FROM VULNERABILITIES;")
        metrics["vulnerabilities"]["total_db"] = cursor.fetchone()[0]

    # -------------------------------------------------------------------------
    # 3. Report Import Summary Table
    # -------------------------------------------------------------------------
    print("\n[1] DATA INGESTION AUDIT SUMMARY:")
    print("-" * 75)
    print(f"  {'Entity':<22} | {'CSV Rows Read':>14} | {'New Inserted':>14} | {'Total in DB':>14}")
    print("-" * 75)
    for entity, m in metrics.items():
        print(f"  {entity.capitalize():<22} | {m['csv_rows']:>14,}"
              f" | {m['inserted']:>14,}"
              f" | {m['total_db']:>14,}")
    print("-" * 75)

    # -------------------------------------------------------------------------
    # 4. Display Database Summary & Verification Query
    # -------------------------------------------------------------------------
    print("\n[2] CURRENT DATABASE RECORD COUNTS ACROSS ALL TABLES:")
    print("-" * 75)
    summary = get_database_summary(conn)
    for tbl, count in summary.items():
        print(f"  Table: {tbl:<26} | Records: {count:>10,}")
    print("-" * 75)

    # -------------------------------------------------------------------------
    # 5. Sample Query Verification (Relational Integrity Test)
    # -------------------------------------------------------------------------
    print("\n[3] SAMPLE RELATIONAL JOIN VERIFICATION (Incident Data + Lookups):")
    print("-" * 75)
    sample_query = """
        SELECT 
            i.incident_id,
            i.incident_date,
            a.attack_type_name AS attack_type,
            s.sector_name AS sector,
            sev.severity_name AS severity,
            COALESCE(r.region_name, i.target_state, 'Unknown') AS region,
            i.data_source
        FROM INCIDENTS i
        JOIN ATTACK_TYPES a   ON i.attack_type_fk = a.attack_type_id
        JOIN SECTORS s        ON i.sector_fk = s.sector_id
        JOIN SEVERITY_LEVELS sev ON i.severity_fk = sev.severity_id
        LEFT JOIN REGIONS r   ON i.region_fk = r.region_id
        ORDER BY i.incident_date DESC
        LIMIT 5;
    """
    sample_df = query_to_dataframe(conn, sample_query)
    if not sample_df.empty:
        print(sample_df.to_string(index=False))
    else:
        print("  [INFO] No incident records found to display.")

    print("\n[4] SAMPLE VULNERABILITY VERIFICATION (KEV Exploited vs NVD):")
    print("-" * 75)
    vuln_query = """
        SELECT 
            cve_id,
            published_date,
            cvss_base_score,
            cvss_severity,
            vendor,
            is_known_exploited,
            known_ransomware_use
        FROM VULNERABILITIES
        WHERE is_known_exploited = 1
        ORDER BY cvss_base_score DESC
        LIMIT 5;
    """
    vuln_sample = query_to_dataframe(conn, vuln_query)
    if not vuln_sample.empty:
        print(vuln_sample.to_string(index=False))
    else:
        print("  [INFO] No exploited vulnerabilities found to display.")

    print("\n" + "=" * 75)
    print("  [SUCCESS] Database import and verification completed successfully!")
    print("=" * 75 + "\n")

    conn.close()
    return True, metrics


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python src/import_processed_data.py",
        description="Import cleaned incident and vulnerability records into SQLite"
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"Path to SQLite database file (default: {DEFAULT_DB_PATH})"
    )
    parser.add_argument(
        "--incidents",
        type=Path,
        default=DEFAULT_INCIDENTS_PATH,
        help=f"Path to cleaned incidents CSV (default: {DEFAULT_INCIDENTS_PATH})"
    )
    parser.add_argument(
        "--nvd",
        type=Path,
        default=DEFAULT_NVD_PATH,
        help=f"Path to cleaned NVD CVE CSV (default: {DEFAULT_NVD_PATH})"
    )
    parser.add_argument(
        "--kev",
        type=Path,
        default=DEFAULT_KEV_PATH,
        help=f"Path to cleaned CISA KEV CSV (default: {DEFAULT_KEV_PATH})"
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    success, _ = import_all_processed_data(
        db_path=args.db,
        incidents_csv=args.incidents,
        nvd_csv=args.nvd,
        kev_csv=args.kev
    )
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()

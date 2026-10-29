"""
src/init_database.py — Schema Initialisation Script for NCTIRAP SQLite Database
===============================================================================
National Cyber Threat Intelligence & Risk Analytics Platform

PURPOSE:
    This standalone script initialises the SQLite relational database schema
    at database/nctirap.db by executing database/schema.sql.
    
    It constructs all required tables:
      - ATTACK_TYPES (and THREAT_TYPES compatibility view)
      - SECTORS (critical infrastructure and academic SCW weights)
      - SEVERITY_LEVELS (scoring weights 0-4)
      - REGIONS (Indian States, UTs, and National scopes)
      - DATA_SOURCES (provenance registry: CERT-In, NVD, CISA KEV)
      - INCIDENTS (cybersecurity incident records with foreign keys)
      - VULNERABILITIES (CVE records with CISA KEV exploitation flags)
      - ANALYTICS_SECTOR_RISK (computed ACRS risk rankings)
      - ANALYTICS_NATIONAL_RISK (computed NCRI national score)

HOW TO RUN:
    python src/init_database.py
    python src/init_database.py --db database/nctirap.db
"""

import argparse
import logging
import sqlite3
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.database import DEFAULT_DB_PATH, DEFAULT_SCHEMA_PATH, get_connection, initialise_database, get_database_summary


def run_initialisation(db_path: Path, schema_path: Path, recreate: bool = False) -> bool:
    """Run end-to-end schema initialisation and report results."""
    print("\n" + "=" * 70)
    print("  NCTIRAP DATABASE SCHEMA INITIALISATION")
    print("  National Cyber Threat Intelligence & Risk Analytics Platform")
    print("=" * 70)
    print(f"Target Database : {db_path}")
    print(f"Schema Script   : {schema_path}")
    print(f"Recreate Mode   : {recreate}")
    print("-" * 70)

    try:
        if recreate and db_path.exists():
            print(f"[INFO] Removing existing database at {db_path} for clean rebuild...")
            db_path.unlink()

        conn = get_connection(db_path)
        initialise_database(conn, schema_path=schema_path)

        # Retrieve table counts to verify creation
        summary = get_database_summary(conn)
        print("\n[SUCCESS] Relational tables and lookup seed data verified:")
        print("-" * 70)
        print(f"  {'Table Name':<28} | {'Current Record Count':>20}")
        print("-" * 70)
        for tbl, count in summary.items():
            print(f"  {tbl:<28} | {count:>20,}")
        print("-" * 70)

        # Verify views
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='view';")
        views = [row[0] for row in cursor.fetchall()]
        print(f"Compatibility Views Created : {', '.join(views)}")
        print("=" * 70)
        print("  Database is ready for processed data ingestion.")
        print("  Next step: Run `python src/import_processed_data.py`")
        print("=" * 70 + "\n")

        conn.close()
        return True

    except Exception as exc:
        print(f"\n[ERROR] Database initialisation failed: {exc}")
        logging.exception("Initialisation failure details:")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python src/init_database.py",
        description="Initialise SQLite database schema for NCTIRAP"
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"Path to SQLite database file (default: {DEFAULT_DB_PATH})"
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=DEFAULT_SCHEMA_PATH,
        help=f"Path to SQL schema file (default: {DEFAULT_SCHEMA_PATH})"
    )
    parser.add_argument(
        "--recreate",
        action="store_true",
        help="Delete existing database file if present and build clean schema from scratch"
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    success = run_initialisation(args.db, args.schema, recreate=args.recreate)
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()

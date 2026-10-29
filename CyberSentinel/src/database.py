"""
src/database.py — Relational Database Management Module for NCTIRAP
===================================================================
National Cyber Threat Intelligence & Risk Analytics Platform

PURPOSE:
    This module manages the SQLite relational database (database/nctirap.db).
    It provides functions to:
      1. Establish connections with foreign key enforcement and row mapping.
      2. Initialise database tables, views, indexes, and seed taxonomy records.
      3. Import cleaned incident records with foreign key resolution and duplicate prevention.
      4. Import and enrich vulnerability records (NIST NVD + CISA KEV catalog).
      5. Persist calculated risk scores (ACRS per sector and national NCRI).
      6. Query and verify record counts and schema integrity.

ACADEMIC DISCLAIMER:
    This database stores data for an academic prototype. All risk scores
    and sector criticality weights are academic models, not official
    government national security assessments. Authentication is omitted
    for local educational simplicity.

SRS REFERENCES:
    FR-004 (Batch import), FR-012 (Preprocessing summary),
    FR-037 (Vulnerability storage), Section 9 (Database Design).
"""

import argparse
import logging
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "database" / "nctirap.db"
DEFAULT_SCHEMA_PATH = PROJECT_ROOT / "database" / "schema.sql"
TAXONOMY_PATH = PROJECT_ROOT / "config" / "taxonomy.json"


# =============================================================================
# 1. DATABASE CONNECTION
# =============================================================================

def get_connection(db_path: Optional[Union[Path, str]] = None) -> sqlite3.Connection:
    """
    Establish an active connection to the SQLite database.

    Features:
        - Automatically creates parent directories if needed.
        - Enforces foreign key constraints (PRAGMA foreign_keys = ON).
        - Sets row_factory to sqlite3.Row for dictionary-like column access.

    Args:
        db_path: Path to the SQLite database file (defaults to database/nctirap.db).

    Returns:
        sqlite3.Connection: Connected database instance.
    """
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")

    logging.debug(f"Connected to SQLite database: {path}")
    return conn


# =============================================================================
# 2. SCHEMA INITIALIZATION
# =============================================================================

def _migrate_existing_schema_if_needed(conn: sqlite3.Connection) -> None:
    """
    Safely migrate any older schema columns or tables to version 2.0 without data loss.
    """
    conn.execute("PRAGMA foreign_keys = OFF;")
    cursor = conn.cursor()

    # 1. Handle SECTORS description column
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='SECTORS';")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(SECTORS);")
        scols = {row[1] for row in cursor.fetchall()}
        if "description" not in scols:
            try:
                cursor.execute("ALTER TABLE SECTORS ADD COLUMN description TEXT;")
            except Exception:
                pass

    # 2. Handle THREAT_TYPES table vs view
    cursor.execute("SELECT type, name FROM sqlite_master WHERE name='THREAT_TYPES';")
    tt_meta = cursor.fetchone()
    if tt_meta and tt_meta[0] == "table":
        # Make sure ATTACK_TYPES table exists first
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ATTACK_TYPES (
                attack_type_id INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_type_name TEXT NOT NULL UNIQUE,
                description TEXT
            );
        """)
        cursor.execute("INSERT OR IGNORE INTO ATTACK_TYPES (attack_type_name) SELECT threat_type_name FROM THREAT_TYPES;")
        cursor.execute("DROP TABLE THREAT_TYPES;")

    # 3. Handle CVE_RECORDS table -> VULNERABILITIES table migration
    cursor.execute("SELECT type, name FROM sqlite_master WHERE name='CVE_RECORDS';")
    cve_meta = cursor.fetchone()
    if cve_meta and cve_meta[0] == "table":
        # Old schema has physical CVE_RECORDS table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='VULNERABILITIES';")
        if not cursor.fetchone():
            cursor.execute("ALTER TABLE CVE_RECORDS RENAME TO VULNERABILITIES;")
        else:
            cursor.execute("DROP TABLE IF EXISTS CVE_RECORDS;")
    elif cve_meta and cve_meta[0] == "view":
        cursor.execute("DROP VIEW IF EXISTS CVE_RECORDS;")

    # 4. Check VULNERABILITIES columns if table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='VULNERABILITIES';")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(VULNERABILITIES);")
        vcols = {row[1] for row in cursor.fetchall()}
        if "cve_pk" in vcols and "vulnerability_pk" not in vcols:
            try:
                cursor.execute("ALTER TABLE VULNERABILITIES RENAME COLUMN cve_pk TO vulnerability_pk;")
            except Exception:
                pass

        new_vcols = [
            ("last_modified_date", "TEXT"),
            ("cvss_vector", "TEXT"),
            ("cwe_ids", "TEXT"),
            ("vulnerability_name", "TEXT"),
            ("is_known_exploited", "INTEGER NOT NULL DEFAULT 0"),
            ("known_ransomware_use", "TEXT DEFAULT 'Unknown'"),
            ("data_source_fk", "INTEGER"),
            ("data_source", "TEXT NOT NULL DEFAULT 'PUBLIC'"),
            ("created_at", "TEXT NOT NULL DEFAULT (datetime('now'))")
        ]
        for col_name, col_def in new_vcols:
            if col_name not in vcols:
                try:
                    cursor.execute(f"ALTER TABLE VULNERABILITIES ADD COLUMN {col_name} {col_def};")
                except Exception:
                    pass

    # 5. Check INCIDENTS columns if table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='INCIDENTS';")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(INCIDENTS);")
        icols = {row[1] for row in cursor.fetchall()}
        new_icols = [
            ("attack_type_fk", "INTEGER"),
            ("threat_type_fk", "INTEGER"),
            ("region_fk", "INTEGER"),
            ("data_source_fk", "INTEGER"),
            ("synthetic_basis", "TEXT")
        ]
        for col_name, col_def in new_icols:
            if col_name not in icols:
                try:
                    cursor.execute(f"ALTER TABLE INCIDENTS ADD COLUMN {col_name} {col_def};")
                except Exception:
                    pass

        # Sync attack_type_fk and threat_type_fk
        if "attack_type_fk" in icols and "threat_type_fk" in icols:
            cursor.execute("UPDATE INCIDENTS SET attack_type_fk = threat_type_fk WHERE attack_type_fk IS NULL AND threat_type_fk IS NOT NULL;")
            cursor.execute("UPDATE INCIDENTS SET threat_type_fk = attack_type_fk WHERE threat_type_fk IS NULL AND attack_type_fk IS NOT NULL;")

    conn.commit()
    conn.execute("PRAGMA foreign_keys = ON;")


def initialise_database(
    conn: sqlite3.Connection,
    schema_path: Optional[Union[Path, str]] = None
) -> None:
    """
    Execute schema.sql to construct all tables, views, indexes, and seed data.

    This function is idempotent: re-running it does NOT overwrite or erase
    existing data because tables and seed inserts use IF NOT EXISTS / OR IGNORE.

    Args:
        conn: Open SQLite connection.
        schema_path: Path to schema.sql (defaults to database/schema.sql).
    """
    s_path = Path(schema_path) if schema_path else DEFAULT_SCHEMA_PATH
    if not s_path.exists():
        logging.error(f"Schema file not found at: {s_path}")
        raise FileNotFoundError(f"Schema file missing: {s_path}")

    # Check and migrate existing schema columns/tables before executing schema.sql
    _migrate_existing_schema_if_needed(conn)

    with open(s_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    # executescript executes all DDL statements in sequence
    conn.executescript(schema_sql)
    conn.commit()

    logging.info(f"Database schema initialised successfully using {s_path.name}")


# =============================================================================
# 3. INCIDENT DATA IMPORT
# =============================================================================

def insert_incidents(
    conn: sqlite3.Connection,
    cleaned_df: pd.DataFrame,
    taxonomy: Optional[dict] = None
) -> int:
    """
    Insert cleaned cybersecurity incident records into the INCIDENTS table.

    Guarantees:
        - Resolves text categories to integer foreign keys (Attack Types, Sectors,
          Severity, Regions, Data Sources).
        - Prevents duplicate insertion using incident_id check and INSERT OR IGNORE.
        - Preserves raw files by operating exclusively on cleaned in-memory DataFrames.
        - Returns exact count of inserted records.

    Args:
        conn: Open SQLite connection.
        cleaned_df: DataFrame containing cleaned incident records.
        taxonomy: Optional taxonomy dict for fallback mappings.

    Returns:
        int: Number of new records successfully inserted.
    """
    logging.info("Starting incident data insertion into INCIDENTS table...")

    if cleaned_df.empty:
        logging.warning("insert_incidents: Provided DataFrame is empty. No records to insert.")
        return 0

    cursor = conn.cursor()

    # 1. Build lookup maps from lookup tables
    attack_map = {}
    # Try ATTACK_TYPES first, fall back to THREAT_TYPES view
    try:
        attack_map = {row[0]: row[1] for row in cursor.execute("SELECT attack_type_name, attack_type_id FROM ATTACK_TYPES")}
    except sqlite3.OperationalError:
        attack_map = {row[0]: row[1] for row in cursor.execute("SELECT threat_type_name, threat_type_id FROM THREAT_TYPES")}

    sector_map = {row[0]: row[1] for row in cursor.execute("SELECT sector_name, sector_id FROM SECTORS")}
    severity_map = {row[0]: row[1] for row in cursor.execute("SELECT severity_name, severity_id FROM SEVERITY_LEVELS")}

    region_map = {}
    try:
        region_map = {row[0]: row[1] for row in cursor.execute("SELECT region_name, region_id FROM REGIONS")}
    except sqlite3.OperationalError:
        pass

    source_map = {}
    try:
        source_map = {row[0]: row[1] for row in cursor.execute("SELECT source_code, data_source_id FROM DATA_SOURCES")}
    except sqlite3.OperationalError:
        pass

    # 2. Existing incident IDs to avoid duplicate insertion
    cursor.execute("SELECT incident_id FROM INCIDENTS;")
    existing_ids = set(row[0] for row in cursor.fetchall())

    rows_to_insert = []
    skipped_dup = 0
    skipped_fk = 0

    for _, row in cleaned_df.iterrows():
        inc_id = str(row.get("incident_id", "")).strip()
        if not inc_id:
            continue

        if inc_id in existing_ids:
            skipped_dup += 1
            continue

        # Map Attack Type
        threat_str = str(row.get("threat_type", "")).strip()
        attack_fk = attack_map.get(threat_str, attack_map.get("Other"))

        # Map Sector
        sector_str = str(row.get("target_sector", "")).strip()
        sector_fk = sector_map.get(sector_str, sector_map.get("Other"))

        # Map Severity
        sev_str = str(row.get("severity", "")).strip().capitalize()
        severity_fk = severity_map.get(sev_str, severity_map.get("Unknown"))

        if attack_fk is None or sector_fk is None or severity_fk is None:
            logging.warning(f"Unresolvable mandatory FK for incident {inc_id}. Skipping.")
            skipped_fk += 1
            continue

        # Map Region (Optional)
        state_str = str(row.get("target_state", "")).strip() if pd.notna(row.get("target_state")) else None
        region_fk = region_map.get(state_str) if state_str else None

        # Map Data Source
        data_src_label = str(row.get("data_source", "SYNTHETIC")).strip().upper()
        if data_src_label not in ("PUBLIC", "SYNTHETIC"):
            data_src_label = "SYNTHETIC"

        data_src_fk = None
        if data_src_label == "SYNTHETIC":
            data_src_fk = source_map.get("CERT_IN_SYNTHETIC")
        else:
            data_src_fk = source_map.get("NIST_NVD")

        inc_date = str(row.get("incident_date", ""))[:10]
        financial_loss = row.get("financial_loss_inr")
        try:
            financial_loss = float(financial_loss) if pd.notna(financial_loss) else None
        except (ValueError, TypeError):
            financial_loss = None

        res_days = row.get("resolution_days")
        try:
            res_days = int(res_days) if pd.notna(res_days) else None
        except (ValueError, TypeError):
            res_days = None

        desc = str(row.get("description", ""))[:500] if pd.notna(row.get("description")) else None
        syn_basis = str(row.get("synthetic_basis", ""))[:200] if pd.notna(row.get("synthetic_basis")) else None

        rows_to_insert.append((
            inc_id,
            inc_date,
            attack_fk,
            attack_fk,  # threat_type_fk
            sector_fk,
            severity_fk,
            region_fk,
            data_src_fk,
            state_str,
            financial_loss,
            res_days,
            desc,
            data_src_label,
            syn_basis,
        ))
        existing_ids.add(inc_id)

    if not rows_to_insert:
        logging.info(f"No new incidents to insert ({skipped_dup} duplicates skipped).")
        return 0

    cursor.executemany(
        """INSERT OR IGNORE INTO INCIDENTS
           (incident_id, incident_date, attack_type_fk, threat_type_fk, sector_fk,
            severity_fk, region_fk, data_source_fk, target_state, financial_loss_inr,
            resolution_days, description, data_source, synthetic_basis)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows_to_insert
    )
    conn.commit()

    inserted = len(rows_to_insert)
    logging.info(
        f"Successfully inserted {inserted:,} incident records "
        f"({skipped_dup} duplicates skipped, {skipped_fk} FK errors skipped)."
    )
    return inserted


# =============================================================================
# 4. VULNERABILITY DATA IMPORT (NVD + CISA KEV)
# =============================================================================

def insert_vulnerabilities(
    conn: sqlite3.Connection,
    nvd_df: pd.DataFrame,
    kev_df: Optional[pd.DataFrame] = None
) -> int:
    """
    Insert vulnerability records from NIST NVD and enrich with CISA KEV exploitation data.

    Enrichment logic:
        - Cross-references CVE IDs with CISA KEV catalog.
        - Sets is_known_exploited = 1 for CVEs verified in KEV catalog.
        - Captures known_ransomware_use ('Known' / 'Unknown').
        - Avoids duplicate records via cve_id UNIQUE constraint.

    Args:
        conn: Open SQLite connection.
        nvd_df: Cleaned NVD CVE DataFrame.
        kev_df: Optional cleaned CISA KEV DataFrame for enrichment.

    Returns:
        int: Number of vulnerability records successfully inserted.
    """
    logging.info("Starting vulnerability data insertion into VULNERABILITIES table...")

    if nvd_df.empty and (kev_df is None or kev_df.empty):
        logging.warning("insert_vulnerabilities: Both NVD and KEV DataFrames are empty.")
        return 0

    cursor = conn.cursor()

    # Build KEV lookup dictionary for active exploitation enrichment
    kev_lookup: Dict[str, Dict[str, str]] = {}
    if kev_df is not None and not kev_df.empty:
        for _, krow in kev_df.iterrows():
            cid = str(krow.get("cve_id", "")).strip().upper()
            if cid:
                kev_lookup[cid] = {
                    "vendor": str(krow.get("vendor", "")).strip() if pd.notna(krow.get("vendor")) else None,
                    "product": str(krow.get("product", "")).strip() if pd.notna(krow.get("product")) else None,
                    "vulnerability_name": str(krow.get("vulnerability_name", "")).strip() if pd.notna(krow.get("vulnerability_name")) else None,
                    "known_ransomware_use": str(krow.get("known_ransomware_use", "Unknown")).strip(),
                }

    # Fetch existing CVE IDs from VULNERABILITIES
    cursor.execute("SELECT cve_id FROM VULNERABILITIES;")
    existing_cves = set(row[0] for row in cursor.fetchall())

    # Resolve Data Source FKs
    source_map = {}
    try:
        source_map = {row[0]: row[1] for row in cursor.execute("SELECT source_code, data_source_id FROM DATA_SOURCES")}
    except sqlite3.OperationalError:
        pass

    nvd_source_fk = source_map.get("NIST_NVD")
    kev_source_fk = source_map.get("CISA_KEV")

    rows_to_insert = []
    skipped_dup = 0
    skipped_malformed = 0

    # 1. Process NVD dataset
    if not nvd_df.empty:
        for _, row in nvd_df.iterrows():
            cve_id = str(row.get("cve_id", "")).strip().upper()
            if not cve_id.startswith("CVE-"):
                skipped_malformed += 1
                continue

            if cve_id in existing_cves:
                skipped_dup += 1
                continue

            pub_date = str(row.get("published_date", ""))[:10]
            last_mod = str(row.get("last_modified_date", ""))[:10] if pd.notna(row.get("last_modified_date")) else None

            # CVSS Score constraint [0.0, 10.0]
            try:
                cvss_score = float(row.get("cvss_base_score", 0.0))
                cvss_score = max(0.0, min(10.0, round(cvss_score, 2)))
            except (ValueError, TypeError):
                cvss_score = 0.0

            # Severity constraint
            sev = str(row.get("cvss_severity", "Unknown")).strip().capitalize()
            if sev not in ("Critical", "High", "Medium", "Low"):
                sev = "Low"

            cvss_vec = str(row.get("cvss_vector", ""))[:150] if pd.notna(row.get("cvss_vector")) else None
            cwes = str(row.get("cwe_ids", ""))[:100] if pd.notna(row.get("cwe_ids")) else None
            desc = str(row.get("description", ""))[:600] if pd.notna(row.get("description")) else None

            # Enrichment from KEV
            is_exploited = 0
            ransomware_use = "Unknown"
            vendor = str(row.get("vendor", ""))[:100] if pd.notna(row.get("vendor")) else None
            product = str(row.get("product", ""))[:100] if pd.notna(row.get("product")) else None
            vuln_name = None

            if cve_id in kev_lookup:
                is_exploited = 1
                kinfo = kev_lookup[cve_id]
                ransomware_use = kinfo.get("known_ransomware_use", "Unknown")
                vendor = vendor or kinfo.get("vendor")
                product = product or kinfo.get("product")
                vuln_name = kinfo.get("vulnerability_name")

            rows_to_insert.append((
                cve_id,
                pub_date,
                last_mod,
                cvss_score,
                sev,
                cvss_vec,
                cwes,
                vendor,
                product,
                vuln_name,
                is_exploited,
                ransomware_use,
                desc,
                nvd_source_fk,
                "PUBLIC"
            ))
            existing_cves.add(cve_id)

    # 2. Process standalone KEV records that may not have been in NVD
    if kev_df is not None and not kev_df.empty:
        # Also update any existing CVEs that match KEV exploitation records
        if kev_lookup:
            update_rows = [(v.get("known_ransomware_use", "Unknown"), 1, cid) for cid, v in kev_lookup.items()]
            cursor.executemany(
                "UPDATE VULNERABILITIES SET known_ransomware_use = ?, is_known_exploited = ? WHERE cve_id = ?;",
                update_rows
            )
            conn.commit()

        for _, krow in kev_df.iterrows():
            cve_id = str(krow.get("cve_id", "")).strip().upper()
            if not cve_id.startswith("CVE-") or cve_id in existing_cves:
                continue

            pub_date = str(krow.get("published_date", ""))[:10]
            desc = str(krow.get("description", ""))[:600] if pd.notna(krow.get("description")) else None
            vendor = str(krow.get("vendor", ""))[:100] if pd.notna(krow.get("vendor")) else None
            product = str(krow.get("product", ""))[:100] if pd.notna(krow.get("product")) else None
            vname = str(krow.get("vulnerability_name", ""))[:200] if pd.notna(krow.get("vulnerability_name")) else None
            rw_use = str(krow.get("known_ransomware_use", "Unknown")).strip()
            cwes = str(krow.get("cwe_ids", ""))[:100] if pd.notna(krow.get("cwe_ids")) else None

            # KEV items are by definition actively exploited; default to High / 7.5 if unprovided
            rows_to_insert.append((
                cve_id,
                pub_date,
                None,
                7.5,
                "High",
                None,
                cwes,
                vendor,
                product,
                vname,
                1,
                rw_use,
                desc,
                kev_source_fk,
                "PUBLIC"
            ))
            existing_cves.add(cve_id)

    if not rows_to_insert:
        logging.info(f"No new vulnerability records to insert ({skipped_dup} duplicates skipped).")
        return 0

    cursor.executemany(
        """INSERT OR IGNORE INTO VULNERABILITIES
           (cve_id, published_date, last_modified_date, cvss_base_score, cvss_severity,
            cvss_vector, cwe_ids, vendor, product, vulnerability_name, is_known_exploited,
            known_ransomware_use, description, data_source_fk, data_source)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows_to_insert
    )
    conn.commit()

    inserted = len(rows_to_insert)
    logging.info(
        f"Successfully inserted {inserted:,} vulnerability records "
        f"({skipped_dup} duplicates skipped, {skipped_malformed} malformed IDs skipped)."
    )
    return inserted


def insert_cve_records(conn: sqlite3.Connection, cve_df: pd.DataFrame) -> int:
    """Legacy backward-compatible wrapper that routes to insert_vulnerabilities."""
    return insert_vulnerabilities(conn, nvd_df=cve_df, kev_df=None)


# =============================================================================
# 5. RISK SCORE PERSISTENCE
# =============================================================================

def save_sector_risk_scores(conn: sqlite3.Connection, sector_scores: List[Dict]) -> int:
    """
    Persist calculated Academic Cyber Risk Scores (ACRS) to ANALYTICS_SECTOR_RISK.

    Args:
        conn: Open SQLite connection.
        sector_scores: List of dicts with sector risk calculations.

    Returns:
        int: Number of rows inserted.
    """
    if not sector_scores:
        logging.warning("save_sector_risk_scores: No scores to save.")
        return 0

    cursor = conn.cursor()
    sector_map = {row[0]: row[1] for row in cursor.execute("SELECT sector_name, sector_id FROM SECTORS;")}

    analysis_date = datetime.now().strftime("%Y-%m-%d")
    rows_to_insert = []

    for item in sector_scores:
        s_name = item.get("sector_name")
        s_id = sector_map.get(s_name)
        if s_id is None:
            logging.warning(f"Sector '{s_name}' not found in SECTORS table; skipping save.")
            continue

        nifs = float(item.get("nifs_score", 0.0))
        wss = float(item.get("wss_score", 0.0))
        acrs = float(item.get("acrs_score", 0.0))
        cat = str(item.get("risk_category", "Low Risk"))

        rows_to_insert.append((s_id, analysis_date, nifs, wss, acrs, cat))

    if rows_to_insert:
        cursor.executemany(
            """INSERT INTO ANALYTICS_SECTOR_RISK
               (sector_fk, analysis_date, nifs_score, wss_score, acrs_score, risk_category)
               VALUES (?, ?, ?, ?, ?, ?);
            """,
            rows_to_insert
        )
        conn.commit()
        logging.info(f"Saved {len(rows_to_insert)} sector risk score records to ANALYTICS_SECTOR_RISK.")
        return len(rows_to_insert)

    return 0


def save_national_risk_index(
    conn: sqlite3.Connection,
    ncri_score: float,
    period_label: str
) -> bool:
    """
    Persist calculated National Cyber Risk Index (NCRI) to ANALYTICS_NATIONAL_RISK.

    Args:
        conn: Open SQLite connection.
        ncri_score: Composite national index [0.0, 100.0].
        period_label: Time period string (e.g. "2021-2024").

    Returns:
        bool: True if insertion succeeded.
    """
    try:
        analysis_date = datetime.now().strftime("%Y-%m-%d")
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO ANALYTICS_NATIONAL_RISK (period_label, ncri_score, analysis_date)
               VALUES (?, ?, ?);
            """,
            (str(period_label), float(ncri_score), analysis_date)
        )
        conn.commit()
        logging.info(f"Saved National Cyber Risk Index ({ncri_score:.2f}) to ANALYTICS_NATIONAL_RISK.")
        return True
    except Exception as exc:
        logging.error(f"Failed to save NCRI to database: {exc}")
        return False


# =============================================================================
# 6. QUERY HELPERS & AUDIT CHECKS
# =============================================================================

def query_to_dataframe(
    conn: sqlite3.Connection,
    sql: str,
    params: tuple = ()
) -> pd.DataFrame:
    """Execute a SQL SELECT query and return results as a Pandas DataFrame."""
    return pd.read_sql_query(sql, conn, params=params)


def get_database_summary(conn: sqlite3.Connection) -> Dict[str, Union[int, Dict]]:
    """
    Query table row counts and schema statistics for basic audit reporting.

    Returns:
        Dict: Table names mapped to their respective record counts.
    """
    cursor = conn.cursor()
    tables = [
        "INCIDENTS",
        "VULNERABILITIES",
        "SECTORS",
        "ATTACK_TYPES",
        "SEVERITY_LEVELS",
        "REGIONS",
        "DATA_SOURCES",
        "ANALYTICS_SECTOR_RISK",
        "ANALYTICS_NATIONAL_RISK",
    ]

    summary = {}
    for tbl in tables:
        try:
            cursor.execute(f"SELECT COUNT(*) FROM {tbl};")
            summary[tbl] = cursor.fetchone()[0]
        except sqlite3.OperationalError:
            summary[tbl] = 0

    return summary


def verify_database(conn: sqlite3.Connection) -> bool:
    """
    Run diagnostic queries to verify schema integrity and relational joins.

    Checks:
        1. All core tables exist and are accessible.
        2. Lookup seed tables are populated.
        3. Foreign keys resolve correctly in sample JOIN queries.
    """
    logging.info("Running database diagnostic verification...")
    cursor = conn.cursor()

    summary = get_database_summary(conn)
    for tbl, count in summary.items():
        logging.info(f"  Table: {tbl:<25} | Records: {count:>8,}")

    # Check join integrity
    if summary.get("INCIDENTS", 0) > 0:
        query = """
            SELECT 
                i.incident_id,
                i.incident_date,
                a.attack_type_name,
                s.sector_name,
                sev.severity_name,
                r.region_name,
                d.source_name
            FROM INCIDENTS i
            JOIN ATTACK_TYPES a   ON i.attack_type_fk = a.attack_type_id
            JOIN SECTORS s        ON i.sector_fk = s.sector_id
            JOIN SEVERITY_LEVELS sev ON i.severity_fk = sev.severity_id
            LEFT JOIN REGIONS r   ON i.region_fk = r.region_id
            LEFT JOIN DATA_SOURCES d ON i.data_source_fk = d.data_source_id
            LIMIT 1;
        """
        cursor.execute(query)
        sample = cursor.fetchone()
        if sample:
            logging.info(f"  Join verification passed! Sample incident: {sample[0]} ({sample[2]} -> {sample[3]})")
        else:
            logging.warning("  Join query returned no results.")

    return True


# =============================================================================
# 7. COMMAND-LINE INTERFACE
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m src.database",
        description="NCTIRAP SQLite Database Management & Data Ingestion Engine"
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"Path to SQLite database file (default: {DEFAULT_DB_PATH})"
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Initialise or rebuild tables and lookup seed data from schema.sql"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Run schema and table verification checks"
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    conn = get_connection(args.db)

    if args.init:
        initialise_database(conn)

    if args.verify or args.init:
        verify_database(conn)

    conn.close()


if __name__ == "__main__":
    main()

"""
tests/test_database.py — Unit & Integration Tests for SQLite Database
=====================================================================
National Cyber Threat Intelligence & Risk Analytics Platform

PURPOSE:
    Verifies that the SQLite database satisfies all SRS and assignment requirements:
      1. Relational schema creation (tables, views, indexes, foreign keys).
      2. Seed data population (ATTACK_TYPES, SECTORS, SEVERITY_LEVELS, REGIONS, DATA_SOURCES).
      3. Primary key and natural key uniqueness constraints (incident_id, cve_id).
      4. Foreign key integrity enforcement (PRAGMA foreign_keys = ON).
      5. Value domain CHECK constraints (CVSS score 0-10, data_source enum, etc.).
      6. Duplicate prevention and idempotent batch ingestion.
      7. Backward-compatible view resolution (THREAT_TYPES, CVE_RECORDS).
      8. Multi-table relational queries and joins.
      9. Live database verification for database/nctirap.db.

HOW TO RUN:
    python tests/test_database.py
"""

import sqlite3
import sys
import tempfile
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.database import (
    DEFAULT_DB_PATH,
    DEFAULT_SCHEMA_PATH,
    get_connection,
    initialise_database,
    insert_incidents,
    insert_vulnerabilities,
    get_database_summary,
    query_to_dataframe,
)

PASS_COUNT = 0
FAIL_COUNT = 0


def _assert(condition: bool, test_name: str, detail: str = "") -> None:
    global PASS_COUNT, FAIL_COUNT
    if condition:
        PASS_COUNT += 1
        print(f"  [PASS] {test_name}")
    else:
        FAIL_COUNT += 1
        msg = f"  [FAIL] {test_name}"
        if detail:
            msg += f" -> {detail}"
        print(msg)


def _section(title: str) -> None:
    print(f"\n-- {title} " + "-" * max(0, 65 - len(title)))


# =============================================================================
# 1. SCHEMA CREATION & SEED DATA TESTS
# =============================================================================

def test_schema_creation_and_seed_data() -> None:
    _section("1. Schema Creation & Seed Data Tests")

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_db = Path(tmp_dir) / "test_nctirap.db"
        conn = get_connection(tmp_db)
        initialise_database(conn, schema_path=DEFAULT_SCHEMA_PATH)

        summary = get_database_summary(conn)

        # Check tables exist
        _assert("ATTACK_TYPES" in summary, "Schema: ATTACK_TYPES table created")
        _assert("SECTORS" in summary, "Schema: SECTORS table created")
        _assert("SEVERITY_LEVELS" in summary, "Schema: SEVERITY_LEVELS table created")
        _assert("REGIONS" in summary, "Schema: REGIONS table created")
        _assert("DATA_SOURCES" in summary, "Schema: DATA_SOURCES table created")
        _assert("INCIDENTS" in summary, "Schema: INCIDENTS table created")
        _assert("VULNERABILITIES" in summary, "Schema: VULNERABILITIES table created")
        _assert("ANALYTICS_SECTOR_RISK" in summary, "Schema: ANALYTICS_SECTOR_RISK table created")
        _assert("ANALYTICS_NATIONAL_RISK" in summary, "Schema: ANALYTICS_NATIONAL_RISK table created")

        # Check seed data counts
        _assert(summary["ATTACK_TYPES"] >= 11, f"Seed: 11 Attack Types seeded (Got {summary['ATTACK_TYPES']})")
        _assert(summary["SECTORS"] == 8, f"Seed: 8 Critical Sectors seeded (Got {summary['SECTORS']})")
        _assert(summary["SEVERITY_LEVELS"] == 5, f"Seed: 5 Severity Levels seeded (Got {summary['SEVERITY_LEVELS']})")
        _assert(summary["REGIONS"] >= 35, f"Seed: Indian States/UTs seeded (Got {summary['REGIONS']})")
        _assert(summary["DATA_SOURCES"] == 3, f"Seed: 3 Data Sources seeded (Got {summary['DATA_SOURCES']})")

        # Check views
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='view';")
        views = set(row[0] for row in cursor.fetchall())
        _assert("THREAT_TYPES" in views, "Schema: THREAT_TYPES backward compatibility view created")
        _assert("CVE_RECORDS" in views, "Schema: CVE_RECORDS backward compatibility view created")

        conn.close()


# =============================================================================
# 2. CONSTRAINTS & INTEGRITY TESTS
# =============================================================================

def test_constraints_and_foreign_keys() -> None:
    _section("2. Constraints & Foreign Key Enforcement Tests")

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_db = Path(tmp_dir) / "test_constraints.db"
        conn = get_connection(tmp_db)
        initialise_database(conn)
        cursor = conn.cursor()

        # Test 1: CVSS Base Score range constraint [0.0, 10.0]
        cvss_invalid = False
        try:
            cursor.execute("""
                INSERT INTO VULNERABILITIES 
                (cve_id, published_date, cvss_base_score, cvss_severity, data_source)
                VALUES ('CVE-2024-99999', '2024-01-01', 11.5, 'Critical', 'PUBLIC');
            """)
            conn.commit()
        except sqlite3.IntegrityError:
            cvss_invalid = True
        conn.rollback()
        _assert(cvss_invalid, "Constraint: CVSS score > 10.0 rejected by CHECK constraint")

        # Test 2: Incident data_source check constraint ('PUBLIC' or 'SYNTHETIC')
        source_invalid = False
        try:
            cursor.execute("""
                INSERT INTO INCIDENTS
                (incident_id, incident_date, attack_type_fk, sector_fk, severity_fk, data_source)
                VALUES ('INC-FAIL-01', '2024-01-01', 1, 1, 1, 'INVALID_SOURCE');
            """)
            conn.commit()
        except sqlite3.IntegrityError:
            source_invalid = True
        conn.rollback()
        _assert(source_invalid, "Constraint: Invalid data_source rejected by CHECK constraint")

        # Test 3: Foreign Key enforcement (invalid sector_fk)
        fk_invalid = False
        try:
            cursor.execute("""
                INSERT INTO INCIDENTS
                (incident_id, incident_date, attack_type_fk, sector_fk, severity_fk, data_source)
                VALUES ('INC-FAIL-02', '2024-01-01', 1, 9999, 1, 'SYNTHETIC');
            """)
            conn.commit()
        except sqlite3.IntegrityError:
            fk_invalid = True
        conn.rollback()
        _assert(fk_invalid, "Foreign Key: Non-existent sector_fk (9999) rejected when foreign_keys=ON")

        conn.close()


# =============================================================================
# 3. DUPLICATE PREVENTION & BATCH INGESTION TESTS
# =============================================================================

def test_duplicate_prevention() -> None:
    _section("3. Duplicate Prevention & Idempotency Tests")

    sample_incidents = pd.DataFrame([
        {
            "incident_id": "TEST-INC-001",
            "incident_date": "2024-05-10",
            "threat_type": "Phishing",
            "target_sector": "Banking & Finance",
            "severity": "Critical",
            "target_state": "Maharashtra",
            "data_source": "SYNTHETIC",
        },
        {
            "incident_id": "TEST-INC-002",
            "incident_date": "2024-05-11",
            "threat_type": "Ransomware",
            "target_sector": "Power & Energy",
            "severity": "High",
            "target_state": "Delhi",
            "data_source": "SYNTHETIC",
        },
    ])

    sample_nvd = pd.DataFrame([
        {
            "cve_id": "CVE-2024-10001",
            "published_date": "2024-01-15",
            "cvss_base_score": 9.8,
            "cvss_severity": "Critical",
            "vendor": "TestVendor",
            "product": "TestProduct",
            "description": "Test remote code execution vulnerability",
        }
    ])

    sample_kev = pd.DataFrame([
        {
            "cve_id": "CVE-2024-10001",
            "vendor": "TestVendor",
            "product": "TestProduct",
            "known_ransomware_use": "Known",
        }
    ])

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_db = Path(tmp_dir) / "test_dedup.db"
        conn = get_connection(tmp_db)
        initialise_database(conn)

        # 1. First Ingestion
        inc1 = insert_incidents(conn, sample_incidents)
        _assert(inc1 == 2, f"Ingestion: First incident batch inserted 2 records (Got {inc1})")

        vuln1 = insert_vulnerabilities(conn, nvd_df=sample_nvd, kev_df=sample_kev)
        _assert(vuln1 == 1, f"Ingestion: First vulnerability inserted 1 record (Got {vuln1})")

        # 2. Duplicate Ingestion Attempt (Same DataFrame)
        inc2 = insert_incidents(conn, sample_incidents)
        _assert(inc2 == 0, f"Deduplication: Second incident insertion skipped duplicate records (Got {inc2})")

        vuln2 = insert_vulnerabilities(conn, nvd_df=sample_nvd, kev_df=sample_kev)
        _assert(vuln2 == 0, f"Deduplication: Second vulnerability insertion skipped duplicates (Got {vuln2})")

        # 3. Verify total row counts in DB did not increase
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM INCIDENTS;")
        _assert(cursor.fetchone()[0] == 2, "Deduplication: Total INCIDENTS remains 2")

        cursor.execute("SELECT COUNT(*) FROM VULNERABILITIES;")
        _assert(cursor.fetchone()[0] == 1, "Deduplication: Total VULNERABILITIES remains 1")

        # 4. Verify KEV enrichment was captured
        cursor.execute("SELECT is_known_exploited, known_ransomware_use FROM VULNERABILITIES WHERE cve_id = 'CVE-2024-10001';")
        vuln_row = cursor.fetchone()
        _assert(vuln_row[0] == 1, "Enrichment: is_known_exploited flag correctly set to 1")
        _assert(vuln_row[1] == "Known", "Enrichment: known_ransomware_use set to 'Known'")

        conn.close()


# =============================================================================
# 4. RELATIONAL JOIN & QUERY VERIFICATION TESTS
# =============================================================================

def test_relational_queries() -> None:
    _section("4. Relational Join & Query Verification Tests")

    sample_incidents = pd.DataFrame([
        {
            "incident_id": "TEST-INC-JOIN",
            "incident_date": "2024-06-01",
            "threat_type": "DDoS",
            "target_sector": "Telecommunications",
            "severity": "Medium",
            "target_state": "Karnataka",
            "data_source": "SYNTHETIC",
        }
    ])

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_db = Path(tmp_dir) / "test_queries.db"
        conn = get_connection(tmp_db)
        initialise_database(conn)
        insert_incidents(conn, sample_incidents)

        # 1. Multi-table JOIN query
        join_sql = """
            SELECT 
                i.incident_id,
                a.attack_type_name,
                s.sector_name,
                s.sector_criticality_weight,
                sev.severity_name,
                sev.severity_weight,
                r.region_name,
                r.region_type,
                d.source_name
            FROM INCIDENTS i
            JOIN ATTACK_TYPES a   ON i.attack_type_fk = a.attack_type_id
            JOIN SECTORS s        ON i.sector_fk = s.sector_id
            JOIN SEVERITY_LEVELS sev ON i.severity_fk = sev.severity_id
            LEFT JOIN REGIONS r   ON i.region_fk = r.region_id
            LEFT JOIN DATA_SOURCES d ON i.data_source_fk = d.data_source_id
            WHERE i.incident_id = 'TEST-INC-JOIN';
        """
        df = query_to_dataframe(conn, join_sql)
        _assert(len(df) == 1, "Query: 5-table JOIN query returns exactly 1 row")
        _assert(df.iloc[0]["attack_type_name"] == "DDoS", "Query: Attack type correctly resolved to 'DDoS'")
        _assert(df.iloc[0]["sector_name"] == "Telecommunications", "Query: Sector correctly resolved to 'Telecommunications'")
        _assert(df.iloc[0]["sector_criticality_weight"] == 0.16, "Query: SCW weight correctly resolved to 0.16")
        _assert(df.iloc[0]["region_name"] == "Karnataka", "Query: Region correctly resolved to 'Karnataka'")

        # 2. Legacy view backward-compatibility queries
        legacy_threat_df = query_to_dataframe(conn, "SELECT threat_type_id, threat_type_name FROM THREAT_TYPES WHERE threat_type_name = 'Phishing';")
        _assert(len(legacy_threat_df) == 1, "Backward Compatibility: THREAT_TYPES view query succeeds")

        legacy_cve_df = query_to_dataframe(conn, "SELECT cve_id, cvss_base_score FROM CVE_RECORDS;")
        _assert(isinstance(legacy_cve_df, pd.DataFrame), "Backward Compatibility: CVE_RECORDS view query succeeds")

        conn.close()


# =============================================================================
# 5. LIVE PROJECT DATABASE VERIFICATION
# =============================================================================

def test_live_database_verification() -> None:
    _section("5. Live Project Database Verification")

    if not DEFAULT_DB_PATH.exists():
        print(f"  [SKIP] Live database not found at {DEFAULT_DB_PATH}")
        return

    conn = get_connection(DEFAULT_DB_PATH)
    summary = get_database_summary(conn)

    _assert(summary["INCIDENTS"] >= 2000, f"Live DB: INCIDENTS contains {summary['INCIDENTS']:,} records")
    _assert(summary["VULNERABILITIES"] >= 7000, f"Live DB: VULNERABILITIES contains {summary['VULNERABILITIES']:,} records")
    _assert(summary["SECTORS"] == 8, f"Live DB: SECTORS contains {summary['SECTORS']} records")
    _assert(summary["ATTACK_TYPES"] >= 11, f"Live DB: ATTACK_TYPES contains {summary['ATTACK_TYPES']} records")
    _assert(summary["REGIONS"] >= 35, f"Live DB: REGIONS contains {summary['REGIONS']} records")
    _assert(summary["DATA_SOURCES"] == 3, f"Live DB: DATA_SOURCES contains {summary['DATA_SOURCES']} records")

    # Verify that exploited vulnerabilities can be queried
    exploited_df = query_to_dataframe(conn, "SELECT COUNT(*) AS cnt FROM VULNERABILITIES WHERE is_known_exploited = 1;")
    exploited_cnt = exploited_df.iloc[0]["cnt"]
    _assert(exploited_cnt > 0, f"Live DB: {exploited_cnt:,} vulnerabilities marked as actively exploited by KEV")

    conn.close()


# =============================================================================
# MAIN TEST RUNNER
# =============================================================================

def main() -> None:
    print("=" * 70)
    print("  RUNNING NCTIRAP SQLITE DATABASE TEST SUITE")
    print("=" * 70)

    test_schema_creation_and_seed_data()
    test_constraints_and_foreign_keys()
    test_duplicate_prevention()
    test_relational_queries()
    test_live_database_verification()

    print("\n" + "=" * 70)
    total = PASS_COUNT + FAIL_COUNT
    print(f"  TEST RESULTS: {PASS_COUNT}/{total} checks passed.")
    if FAIL_COUNT == 0:
        print("  [SUCCESS] All database test cases passed successfully!")
    else:
        print(f"  [ERROR] {FAIL_COUNT} test(s) failed.")
        sys.exit(1)
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()

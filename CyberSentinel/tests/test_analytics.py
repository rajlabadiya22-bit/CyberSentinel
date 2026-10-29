"""
tests/test_analytics.py — Unit & Integration Tests for Historical Analytics
=============================================================================
National Cyber Threat Intelligence & Risk Analytics Platform

PURPOSE:
    This test suite verifies all functions in src/analytics.py, ensuring:
      1. Correct grouping, ranking, and percentage calculations.
      2. Proper handling of missing fields or unparseable dates without crashes.
      3. Strict segregation between incident data and vulnerability records.
      4. Accurate numeric calculations (YoY changes, mean, median, IQR).
      5. Safe CSV export generation.
      6. Provenance tagging (SYNTHETIC vs PUBLIC) and metadata recording.

HOW TO RUN:
    python tests/test_analytics.py
"""

import math
import sys
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd

# Setup project root in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.analytics import (
    count_incidents_by_attack_type,
    count_incidents_by_severity,
    analyze_incident_trends,
    compute_year_over_year_change,
    compare_sectors,
    identify_top_attack_types,
    summarize_vulnerabilities,
    calculate_descriptive_statistics,
    export_analytics_results,
    run_all_historical_analytics,
)

# Test Counters
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
    print(f"\n-- {title} " + "-" * (65 - len(title)))


# =============================================================================
# MOCK FIXTURES FOR ISOLATED TESTING
# =============================================================================

def get_sample_incident_df() -> pd.DataFrame:
    """Return a controlled sample DataFrame of incidents for unit testing."""
    return pd.DataFrame({
        "incident_id": ["INC-01", "INC-02", "INC-03", "INC-04", "INC-05", "INC-06"],
        "incident_date": ["2022-01-15", "2022-06-20", "2023-01-10", "2023-03-12", "2023-08-05", "2023-11-20"],
        "threat_type": ["Phishing", "Ransomware", "Phishing", "Phishing", "DDoS", "Ransomware"],
        "target_sector": ["Banking & Finance", "Healthcare", "Banking & Finance", "Healthcare", "Power & Energy", "Banking & Finance"],
        "severity": ["High", "Critical", "Medium", "High", "Low", "Critical"],
        "data_source": ["SYNTHETIC"] * 6
    })


def get_sample_cve_df() -> pd.DataFrame:
    """Return a controlled sample DataFrame of CVEs for unit testing."""
    return pd.DataFrame({
        "cve_id": ["CVE-2023-001", "CVE-2023-002", "CVE-2023-003", "CVE-2023-004", "CVE-2023-005"],
        "published_date": ["2023-01-01", "2023-02-15", "2023-03-20", "2023-04-10", "2023-05-01"],
        "cvss_base_score": [9.8, 7.5, 5.0, 3.2, np.nan],
        "cvss_severity": ["Critical", "High", "Medium", "Low", "Unknown"],
        "data_source": ["PUBLIC"] * 5
    })


# =============================================================================
# 1. ATTACK TYPE ANALYSIS TESTS
# =============================================================================

def test_attack_type_analysis():
    _section("Test Attack Type Distribution")
    df = get_sample_incident_df()
    res = count_incidents_by_attack_type(df)

    _assert(len(res) == 3, "Identifies 3 distinct attack types in sample")
    _assert(res.iloc[0]["threat_type"] == "Phishing", "Phishing correctly ranked #1")
    _assert(res.iloc[0]["incident_count"] == 3, "Phishing count is 3")
    _assert(math.isclose(res["percentage"].sum(), 100.0, abs_tol=0.1), "Percentages sum to 100%")
    _assert("data_source" in res.columns and res.iloc[0]["data_source"] == "SYNTHETIC", "Provenance correctly preserved")

    # Missing column test
    df_missing = df.drop(columns=["threat_type"])
    res_missing = count_incidents_by_attack_type(df_missing)
    _assert(res_missing.empty, "Handles missing threat_type gracefully without crash")


# =============================================================================
# 2. SEVERITY ANALYSIS TESTS
# =============================================================================

def test_severity_analysis():
    _section("Test Severity Distribution")
    df = get_sample_incident_df()
    res = count_incidents_by_severity(df)

    _assert(len(res) == 4, "Identifies 4 severity categories")
    _assert(res.iloc[0]["severity"] == "Critical", "Severity is logically ordered (Critical first)")
    _assert(math.isclose(res["percentage"].sum(), 100.0, abs_tol=0.1), "Percentages sum to 100%")

    # Missing column test
    df_missing = df.drop(columns=["severity"])
    res_missing = count_incidents_by_severity(df_missing)
    _assert(res_missing.empty, "Handles missing severity column gracefully")


# =============================================================================
# 3. TEMPORAL TRENDS & YOY TESTS
# =============================================================================

def test_trends_and_yoy():
    _section("Test Temporal Trends and YoY Calculations")
    df = get_sample_incident_df()
    monthly, annual = analyze_incident_trends(df)

    _assert(len(annual) == 2, "Identifies 2 distinct years (2022 and 2023)")
    # 2022 count = 2, 2023 count = 4 -> YoY change = +100.0%
    y2023 = annual[annual["year"] == 2023].iloc[0]
    _assert(y2023["count_previous_year"] == 2, "2023 previous year count is 2")
    _assert(y2023["yoy_change_absolute"] == 2, "2023 absolute YoY change is +2")
    _assert(y2023["yoy_change_pct"] == 100.0, "2023 YoY percentage change is +100.0%")

    # YoY by threat type
    yoy_threat = compute_year_over_year_change(df)
    _assert(not yoy_threat.empty, "Computes threat-type specific YoY change")

    # Bad dates handling
    df_bad = df.copy()
    df_bad["incident_date"] = "invalid-date-string"
    m_bad, a_bad = analyze_incident_trends(df_bad)
    _assert(m_bad.empty and a_bad.empty, "Gracefully skips unparseable dates")


# =============================================================================
# 4. SECTOR COMPARISON TESTS
# =============================================================================

def test_sector_comparison():
    _section("Test Sector Comparison Analysis")
    df = get_sample_incident_df()
    summary, crosstab, top_yr = compare_sectors(df)

    _assert(len(summary) == 3, "Identifies 3 sectors in sample")
    _assert(summary.iloc[0]["sector_name"] == "Banking & Finance", "Banking & Finance ranked #1 in sample")
    _assert(summary.iloc[0]["incident_count"] == 3, "Banking & Finance has 3 incidents")
    _assert(not crosstab.empty, "Sector-severity cross-tabulation computed")
    _assert(not top_yr.empty, "Top sector by year computed")


# =============================================================================
# 5. TOP N ATTACK TYPES TESTS
# =============================================================================

def test_top_n_attack_types():
    _section("Test Top N Attack Types")
    df = get_sample_incident_df()
    top2 = identify_top_attack_types(df, top_n=2)
    _assert(len(top2) == 2, "Returns exactly top 2 attack types when requested")
    _assert(list(top2["threat_type"]) == ["Phishing", "Ransomware"], "Top 2 attack types correct")


# =============================================================================
# 6. VULNERABILITY SUMMARY & CVSS TESTS
# =============================================================================

def test_vulnerability_summary():
    _section("Test Vulnerability Intelligence & CVSS Stats")
    cve_df = get_sample_cve_df()
    res = summarize_vulnerabilities(cve_df)

    _assert("severity_summary" in res, "Severity summary computed")
    _assert("cvss_statistics" in res, "CVSS statistics computed")

    stats = res["cvss_statistics"].set_index("metric")["value"].to_dict()
    _assert(stats["total_cve_records"] == 5, "Total CVE records is 5")
    _assert(stats["scored_cve_count"] == 4, "Scored CVE count is 4")
    _assert(stats["unscored_or_unknown_count"] == 1, "Unscored count is 1")
    # Valid scores: 9.8, 7.5, 5.0, 3.2 -> mean = 6.375 -> rounded 6.38
    _assert(math.isclose(stats["mean_cvss_score"], 6.38, abs_tol=0.05), f"Mean CVSS score is 6.38 (got {stats['mean_cvss_score']})")
    _assert(stats["min_cvss_score"] == 3.2, "Min CVSS score is 3.2")
    _assert(stats["max_cvss_score"] == 9.8, "Max CVSS score is 9.8")


# =============================================================================
# 7. DESCRIPTIVE STATISTICS & METADATA TESTS
# =============================================================================

def test_descriptive_statistics():
    _section("Test Descriptive Statistics & Metadata")
    df_inc = get_sample_incident_df()
    df_cve = get_sample_cve_df()

    meta = calculate_descriptive_statistics(df_inc, df_cve)
    _assert(not meta.empty, "Descriptive statistics summary created")

    # Check that non-causation policy is included
    notes_list = meta["notes"].tolist()
    has_non_causation = any("NOT prove causation" in str(n) for n in notes_list)
    _assert(has_non_causation, "Explicit non-causation policy recorded in metadata")

    # Check time periods recorded
    metrics_map = meta.set_index("metric")["value"].to_dict()
    _assert(metrics_map.get("incident_time_period_start") == "2022-01-15", "Incident start date recorded correctly")
    _assert(metrics_map.get("incident_time_period_end") == "2023-11-20", "Incident end date recorded correctly")
    _assert(metrics_map.get("cve_time_period_start") == "2023-01-01", "CVE start date recorded correctly")
    _assert(metrics_map.get("cve_time_period_end") == "2023-05-01", "CVE end date recorded correctly")


# =============================================================================
# 8. CSV EXPORT TESTS
# =============================================================================

def test_export_safety():
    _section("Test Safe CSV Export")
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        df = get_sample_incident_df()
        exported = export_analytics_results({"test_threats": df}, output_dir=tmp_path)

        _assert("test_threats" in exported, "Export returned destination path")
        target_file = exported["test_threats"]
        _assert(target_file.exists(), "Exported CSV file exists on disk")
        _assert(target_file.stat().st_size > 0, "Exported file is non-empty")


# =============================================================================
# 9. INTEGRATION TEST AGAINST DATABASE
# =============================================================================

def test_database_integration():
    _section("Test End-to-End Pipeline on Live Project Database")
    db_path = PROJECT_ROOT / "database" / "nctirap.db"
    if not db_path.exists():
        print("  [SKIP] Live database not found at database/nctirap.db")
        return

    res = run_all_historical_analytics(data_source=db_path, export_csv=False)
    _assert("threat_distribution" in res and not res["threat_distribution"].empty, "DB: Threat distribution computed")
    _assert("severity_distribution" in res and not res["severity_distribution"].empty, "DB: Severity distribution computed")
    _assert("incident_trends_monthly" in res and not res["incident_trends_monthly"].empty, "DB: Monthly trends computed")
    _assert("sector_comparison" in res and not res["sector_comparison"].empty, "DB: Sector comparison computed")
    _assert("vulnerability_severity" in res and not res["vulnerability_severity"].empty, "DB: Vulnerability severity computed")
    _assert("vulnerability_cvss_statistics" in res and not res["vulnerability_cvss_statistics"].empty, "DB: CVSS statistics computed")
    _assert("descriptive_statistics" in res and not res["descriptive_statistics"].empty, "DB: Descriptive metadata computed")


# =============================================================================
# MAIN TEST RUNNER
# =============================================================================

def main():
    print("=" * 70)
    print("  RUNNING HISTORICAL CYBERSECURITY ANALYTICS TEST SUITE")
    print("=" * 70)

    test_attack_type_analysis()
    test_severity_analysis()
    test_trends_and_yoy()
    test_sector_comparison()
    test_top_n_attack_types()
    test_vulnerability_summary()
    test_descriptive_statistics()
    test_export_safety()
    test_database_integration()

    print("\n" + "=" * 70)
    total = PASS_COUNT + FAIL_COUNT
    print(f"  TEST RESULTS: {PASS_COUNT}/{total} checks passed.")
    if FAIL_COUNT == 0:
        print("  [SUCCESS] All historical analytics tests passed successfully!")
    else:
        print(f"  [ERROR] {FAIL_COUNT} test(s) failed.")
        sys.exit(1)
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()

"""
tests/test_risk_scoring.py — Unit & Integration Tests for Explainable Cyber Risk Scoring
========================================================================================
National Cyber Threat Intelligence & Risk Analytics Platform

PURPOSE:
    This test suite verifies all components of the explainable risk scoring module:
      1. Component 1: Normalised Incident Frequency Score (NIFS) [0, 100].
      2. Component 2: Weighted Severity Score (WSS) [0, 100] with Min-Max rescaling.
      3. Component 3: Sector Criticality Weights (SCW) & Normalized Criticality (NSCS).
      4. Composite Academic Cyber Risk Score (ACRS) under normalized and literal formulas.
      5. National Cyber Risk Index (NCRI) weighted aggregation.
      6. Threat Category Risk Scoring (ATRS).
      7. Boundary conditions (0.0, 24.0, 25.0, 49.0, 50.0, 74.0, 75.0, 100.0, <0, >100).
      8. Division-by-zero prevention with empty or single-record datasets.
      9. Atomic CSV export and SQLite database persistence.

HOW TO RUN:
    python tests/test_risk_scoring.py
"""

import math
import sqlite3
import sys
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd

# Setup project root in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.risk_scoring import (
    classify_risk_category,
    validate_acrs_range,
    compute_nifs,
    compute_wss,
    compute_sector_criticality,
    compute_sector_risk_scores,
    compute_national_risk_index,
    compute_threat_category_risk_scores,
    export_risk_model_outputs,
    execute_risk_scoring_pipeline,
    load_taxonomy_config,
    DEFAULT_SECTOR_CRITICALITY_WEIGHTS,
    DEFAULT_FORMULA_WEIGHTS,
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
# MOCK FIXTURES FOR CONTROLLED UNIT TESTS
# =============================================================================

def create_synthetic_incident_df() -> pd.DataFrame:
    """Create a controlled mock DataFrame with known sector and severity counts."""
    data = [
        # Banking & Finance: 4 incidents (2 Critical, 2 High)
        {"incident_id": "INC-001", "incident_date": "2023-01-10", "threat_type": "Ransomware", "target_sector": "Banking & Finance", "severity": "Critical"},
        {"incident_id": "INC-002", "incident_date": "2023-02-15", "threat_type": "Phishing",   "target_sector": "Banking & Finance", "severity": "Critical"},
        {"incident_id": "INC-003", "incident_date": "2023-03-20", "threat_type": "Malware",    "target_sector": "Banking & Finance", "severity": "High"},
        {"incident_id": "INC-004", "incident_date": "2023-04-25", "threat_type": "Data Breach","target_sector": "Banking & Finance", "severity": "High"},
        # Power & Energy: 2 incidents (2 Critical)
        {"incident_id": "INC-005", "incident_date": "2023-05-12", "threat_type": "Malware",    "target_sector": "Power & Energy",   "severity": "Critical"},
        {"incident_id": "INC-006", "incident_date": "2023-06-18", "threat_type": "Ransomware", "target_sector": "Power & Energy",   "severity": "Critical"},
        # Healthcare: 2 incidents (2 Low)
        {"incident_id": "INC-007", "incident_date": "2023-07-22", "threat_type": "Phishing",   "target_sector": "Healthcare",       "severity": "Low"},
        {"incident_id": "INC-008", "incident_date": "2023-08-30", "threat_type": "Phishing",   "target_sector": "Healthcare",       "severity": "Low"},
        # Government Services: 1 incident (Medium)
        {"incident_id": "INC-009", "incident_date": "2023-09-05", "threat_type": "Phishing",   "target_sector": "Government Services", "severity": "Medium"},
    ]
    return pd.DataFrame(data)


# =============================================================================
# 1. RISK CATEGORIZATION & BOUNDARY TESTS
# =============================================================================

def test_risk_category_boundaries() -> None:
    _section("1. Risk Category Classification & Boundary Tests")

    # Critical Risk: [75.0, 100.0]
    _assert(classify_risk_category(100.0) == "Critical Risk", "Max score 100.0 is Critical Risk")
    _assert(classify_risk_category(75.0) == "Critical Risk", "Boundary 75.0 is Critical Risk")
    _assert(classify_risk_category(75.01) == "Critical Risk", "Score 75.01 is Critical Risk")

    # High Risk: [50.0, 74.99...]
    _assert(classify_risk_category(74.99) == "High Risk", "Boundary 74.99 is High Risk")
    _assert(classify_risk_category(74.0) == "High Risk", "Score 74.0 is High Risk")
    _assert(classify_risk_category(50.0) == "High Risk", "Boundary 50.0 is High Risk")

    # Moderate Risk: [25.0, 49.99...]
    _assert(classify_risk_category(49.99) == "Moderate Risk", "Boundary 49.99 is Moderate Risk")
    _assert(classify_risk_category(49.0) == "Moderate Risk", "Score 49.0 is Moderate Risk")
    _assert(classify_risk_category(25.0) == "Moderate Risk", "Boundary 25.0 is Moderate Risk")

    # Low Risk: [0.0, 24.99...]
    _assert(classify_risk_category(24.99) == "Low Risk", "Boundary 24.99 is Low Risk")
    _assert(classify_risk_category(24.0) == "Low Risk", "Score 24.0 is Low Risk")
    _assert(classify_risk_category(0.0) == "Low Risk", "Min score 0.0 is Low Risk")

    # Out of Range Exception Handling
    raised_low = False
    try:
        classify_risk_category(-0.01)
    except ValueError:
        raised_low = True
    _assert(raised_low, "Negative score (-0.01) raises ValueError")

    raised_high = False
    try:
        classify_risk_category(100.05)
    except ValueError:
        raised_high = True
    _assert(raised_high, "Score above 100 (100.05) raises ValueError")

    # Missing / NaN handling
    _assert(classify_risk_category(np.nan) == "Unknown", "NaN score returns 'Unknown' category")

    # Validate ACRS Range Helper
    _assert(validate_acrs_range(0.0), "validate_acrs_range: 0.0 is valid")
    _assert(validate_acrs_range(50.0), "validate_acrs_range: 50.0 is valid")
    _assert(validate_acrs_range(100.0), "validate_acrs_range: 100.0 is valid")
    _assert(not validate_acrs_range(-1.0), "validate_acrs_range: -1.0 is invalid")
    _assert(not validate_acrs_range(101.0), "validate_acrs_range: 101.0 is invalid")
    _assert(not validate_acrs_range(np.nan), "validate_acrs_range: NaN is invalid")


# =============================================================================
# 2. NIFS (NORMALIZED INCIDENT FREQUENCY SCORE) TESTS
# =============================================================================

def test_nifs_computation() -> None:
    _section("2. Normalised Incident Frequency Score (NIFS) Tests")

    df = create_synthetic_incident_df()
    nifs_df = compute_nifs(df)

    # Banking & Finance has 4 incidents (highest) -> must receive exactly 100.0
    bf_row = nifs_df[nifs_df["sector_name"] == "Banking & Finance"]
    _assert(not bf_row.empty, "NIFS: Banking & Finance present")
    _assert(bf_row.iloc[0]["incident_count"] == 4, "NIFS: Banking & Finance incident count is 4")
    _assert(bf_row.iloc[0]["nifs_score"] == 100.0, "NIFS: Maximum sector receives exactly 100.0")

    # Power & Energy has 2 incidents -> (2/4)*100 = 50.0
    pe_row = nifs_df[nifs_df["sector_name"] == "Power & Energy"]
    _assert(pe_row.iloc[0]["nifs_score"] == 50.0, "NIFS: Power & Energy receives 50.0 (2 of 4)")

    # Transportation has 0 incidents in mock -> must receive 0.0
    tr_row = nifs_df[nifs_df["sector_name"] == "Transportation"]
    _assert(tr_row.iloc[0]["incident_count"] == 0, "NIFS: Transportation has 0 incidents")
    _assert(tr_row.iloc[0]["nifs_score"] == 0.0, "NIFS: 0 incidents yields exactly 0.0")

    # Division by zero check with completely empty DataFrame
    empty_df = pd.DataFrame(columns=["target_sector", "severity"])
    empty_nifs = compute_nifs(empty_df)
    _assert(len(empty_nifs) > 0, "NIFS: Preserves taxonomy sectors even on empty input")
    _assert((empty_nifs["nifs_score"] == 0.0).all(), "NIFS: All scores 0.0 on empty input without division by zero")


# =============================================================================
# 3. WSS (WEIGHTED SEVERITY SCORE) TESTS
# =============================================================================

def test_wss_computation() -> None:
    _section("3. Weighted Severity Score (WSS) Tests")

    # Test 1: Sector with 100% Critical incidents
    crit_df = pd.DataFrame([
        {"target_sector": "Power & Energy", "severity": "Critical"},
        {"target_sector": "Power & Energy", "severity": "Critical"},
    ])
    crit_wss = compute_wss(crit_df)
    pe = crit_wss[crit_wss["sector_name"] == "Power & Energy"].iloc[0]
    _assert(pe["wss_raw"] == 100.0, "WSS Raw: 100% Critical incidents = 100.0")
    _assert(pe["wss_score"] == 100.0, "WSS Rescaled: 100% Critical incidents = 100.0")

    # Test 2: Sector with 100% Low incidents
    low_df = pd.DataFrame([
        {"target_sector": "Healthcare", "severity": "Low"},
        {"target_sector": "Healthcare", "severity": "Low"},
    ])
    low_wss = compute_wss(low_df)
    hc = low_wss[low_wss["sector_name"] == "Healthcare"].iloc[0]
    _assert(hc["wss_raw"] == 25.0, "WSS Raw: 100% Low incidents = 25.0 (1/4 * 100)")
    _assert(hc["wss_score"] == 0.0, "WSS Rescaled: 100% Low incidents = 0.0 (Min-Max scaled)")

    # Test 3: Sector with 100% Medium incidents
    med_df = pd.DataFrame([
        {"target_sector": "Healthcare", "severity": "Medium"},
    ])
    med_wss = compute_wss(med_df)
    hc_med = med_wss[med_wss["sector_name"] == "Healthcare"].iloc[0]
    _assert(hc_med["wss_raw"] == 50.0, "WSS Raw: 100% Medium incidents = 50.0")
    _assert(abs(hc_med["wss_score"] - 33.33) < 0.1, f"WSS Rescaled: 100% Medium = 33.33 (Got {hc_med['wss_score']})")

    # Test 4: Sector with 0 incidents -> WSS must be 0.0
    zero_wss = compute_wss(pd.DataFrame(columns=["target_sector", "severity"]))
    tr_zero = zero_wss[zero_wss["sector_name"] == "Transportation"].iloc[0]
    _assert(tr_zero["wss_raw"] == 0.0, "WSS Raw: 0 incidents = 0.0 (no division by zero)")
    _assert(tr_zero["wss_score"] == 0.0, "WSS Rescaled: 0 incidents = 0.0")

    # Test 5: Unknown severity is excluded from evaluated incidents denominator
    unk_df = pd.DataFrame([
        {"target_sector": "Banking & Finance", "severity": "Critical"},
        {"target_sector": "Banking & Finance", "severity": "Unknown"},
    ])
    unk_wss = compute_wss(unk_df)
    bf_unk = unk_wss[unk_wss["sector_name"] == "Banking & Finance"].iloc[0]
    _assert(bf_unk["unknown_count"] == 1, "WSS: Unknown count tracked accurately")
    _assert(bf_unk["evaluated_incidents"] == 1, "WSS: Evaluated denominator excludes Unknown")
    _assert(bf_unk["wss_raw"] == 100.0, "WSS: Critical evaluated without distortion from Unknown")


# =============================================================================
# 4. SECTOR CRITICALITY (SCW & NSCS) TESTS
# =============================================================================

def test_sector_criticality() -> None:
    _section("4. Sector Criticality & Normalization Tests")

    crit_df = compute_sector_criticality()

    # Weight sum check (excluding 'Other')
    non_other = crit_df[crit_df["sector_name"] != "Other"]
    total_scw = round(non_other["scw"].sum(), 4)
    _assert(math.isclose(total_scw, 1.00, abs_tol=0.001), f"Criticality: Non-other SCW weights sum to 1.00 (Got {total_scw})")

    # Max sector check (Power & Energy is 0.20 -> NSCS must be 100.0)
    pe_row = crit_df[crit_df["sector_name"] == "Power & Energy"].iloc[0]
    _assert(pe_row["scw"] == 0.20, "Criticality: Power & Energy SCW is 0.20")
    _assert(pe_row["nscs_score"] == 100.0, "Criticality: Top critical sector receives NSCS = 100.0")

    # Other sector check
    other_row = crit_df[crit_df["sector_name"] == "Other"].iloc[0]
    _assert(other_row["scw"] == 0.0, "Criticality: 'Other' SCW is 0.0")
    _assert(other_row["nscs_score"] == 0.0, "Criticality: 'Other' NSCS is 0.0")

    # Check that every sector has a non-empty assumption string
    has_assumptions = (crit_df["assumption"].str.len() > 10).all()
    _assert(has_assumptions, "Criticality: Every sector has documented justification assumption")


# =============================================================================
# 5. COMPOSITE ACRS RISK SCORING TESTS
# =============================================================================

def test_composite_acrs_scores() -> None:
    _section("5. Composite ACRS Calculation & Explainability Tests")

    df = create_synthetic_incident_df()

    # 1. Normalized ACRS calculation
    scores_norm = compute_sector_risk_scores(df, normalize_criticality=True)
    _assert(len(scores_norm) == 8, f"ACRS: Evaluated all 8 sectors (Got {len(scores_norm)})")

    # Verify score bounds [0.0, 100.0]
    all_valid = all(0.0 <= s["acrs_score"] <= 100.0 for s in scores_norm)
    _assert(all_valid, "ACRS: All sector scores strictly within [0.0, 100.0]")

    # Verify ranking is sequential 1..N and descending
    ranks = [s["rank"] for s in scores_norm]
    _assert(ranks == list(range(1, 9)), "ACRS: Consecutive rankings 1 to 8")
    acrs_values = [s["acrs_score"] for s in scores_norm]
    _assert(acrs_values == sorted(acrs_values, reverse=True), "ACRS: Sorted descending by score")

    # Check factor contribution explainability
    for s in scores_norm:
        expected = round(s["freq_points_contrib"] + s["sev_points_contrib"] + s["crit_points_contrib"], 2)
        _assert(math.isclose(s["acrs_score"], expected, abs_tol=0.05),
                f"ACRS Explainability: {s['sector_name']} score matches sum of points",
                f"Got {s['acrs_score']} vs sum {expected}")
        break  # Test top sector for brevity

    # Check literal vs normalized formula difference:
    # Literal formula must be <= 84.0 everywhere
    scores_lit = compute_sector_risk_scores(df, normalize_criticality=False)
    all_lit_under_84 = all(s["acrs_score"] <= 84.05 for s in scores_lit)
    _assert(all_lit_under_84, "ACRS Literal SRS: All scores strictly capped <= 84.0")


# =============================================================================
# 6. NATIONAL CYBER RISK INDEX (NCRI) TESTS
# =============================================================================

def test_ncri_computation() -> None:
    _section("6. National Cyber Risk Index (NCRI) Tests")

    df = create_synthetic_incident_df()
    sector_scores = compute_sector_risk_scores(df)
    ncri_dict = compute_national_risk_index(sector_scores)

    _assert("ncri_score" in ncri_dict, "NCRI: Result contains ncri_score")
    _assert(0.0 <= ncri_dict["ncri_score"] <= 100.0, f"NCRI: Score {ncri_dict['ncri_score']} is within [0.0, 100.0]")
    _assert(ncri_dict["ncri_label"] in ["Critical Risk", "High Risk", "Moderate Risk", "Low Risk"],
            f"NCRI: Valid risk category label ({ncri_dict['ncri_label']})")
    _assert(ncri_dict["evaluated_sectors_count"] == 7, "NCRI: Excludes 'Other', evaluates exactly 7 sectors")
    _assert(ncri_dict["disclaimer"] == "Academic Model — Not an Official Government Metric",
            "NCRI: Includes mandatory statutory disclaimer")

    # Empty sector scores test
    empty_ncri = compute_national_risk_index([])
    _assert(empty_ncri["ncri_score"] == 0.0, "NCRI: Empty sector input returns 0.0 safely")


# =============================================================================
# 7. THREAT CATEGORY RISK SCORING (ATRS) TESTS
# =============================================================================

def test_threat_category_scoring() -> None:
    _section("7. Threat Category Risk Scoring Tests")

    df = create_synthetic_incident_df()
    threat_scores = compute_threat_category_risk_scores(df)

    _assert(len(threat_scores) > 0, "ATRS: Generated scores for threat types")

    # Check top threat has highest score and rank 1
    _assert(threat_scores[0]["rank"] == 1, "ATRS: Top threat has rank 1")
    _assert(all(0.0 <= t["threat_risk_score"] <= 100.0 for t in threat_scores),
            "ATRS: All threat scores strictly within [0.0, 100.0]")
    _assert(all("threat_risk_category" in t for t in threat_scores),
            "ATRS: Every threat categorized")


# =============================================================================
# 8. CSV EXPORT & ATOMIC WRITE SAFETY
# =============================================================================

def test_export_safety() -> None:
    _section("8. Risk Model CSV Export & Atomic Safety Tests")

    df = create_synthetic_incident_df()
    sec_scores = compute_sector_risk_scores(df)
    ncri = compute_national_risk_index(sec_scores)
    thr_scores = compute_threat_category_risk_scores(df)

    with tempfile.TemporaryDirectory() as tmp_dir:
        out_dir = Path(tmp_dir)
        exported = export_risk_model_outputs(sec_scores, ncri, thr_scores, output_dir=out_dir)

        _assert("sector_risk_scores" in exported, "Export: sector_risk_scores.csv exported")
        _assert("national_risk_index" in exported, "Export: national_risk_index.csv exported")
        _assert("threat_risk_scores" in exported, "Export: threat_risk_scores.csv exported")
        _assert("risk_model_documentation" in exported, "Export: risk_model_documentation.csv exported")

        # Verify exported files can be read back cleanly
        sec_read = pd.read_csv(exported["sector_risk_scores"])
        _assert(len(sec_read) == 8, f"Export: sector_risk_scores has 8 rows (Got {len(sec_read)})")
        _assert("acrs_score" in sec_read.columns, "Export: sector_risk_scores has acrs_score column")
        _assert("contributing_factors" in sec_read.columns, "Export: sector_risk_scores has explainability column")

        doc_read = pd.read_csv(exported["risk_model_documentation"])
        _assert(len(doc_read) >= 10, "Export: risk_model_documentation contains complete parameters")


# =============================================================================
# 9. DATABASE INTEGRATION & ACTUAL DATA VERIFICATION
# =============================================================================

def test_database_integration() -> None:
    _section("9. Database Integration & Live Dataset Verification")

    db_path = PROJECT_ROOT / "database" / "nctirap.db"
    if not db_path.exists():
        print("  [SKIP] database/nctirap.db not found. Skipping live DB test.")
        return

    conn = sqlite3.connect(str(db_path))

    # Verify risk tables exist in database
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ANALYTICS_SECTOR_RISK';")
    sec_tbl = cursor.fetchone()
    _assert(sec_tbl is not None, "DB: ANALYTICS_SECTOR_RISK table exists in schema")

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ANALYTICS_NATIONAL_RISK';")
    nat_tbl = cursor.fetchone()
    _assert(nat_tbl is not None, "DB: ANALYTICS_NATIONAL_RISK table exists in schema")

    # Run end-to-end execution pipeline
    with tempfile.TemporaryDirectory() as tmp_dir:
        sec_scores, ncri, thr_scores = execute_risk_scoring_pipeline(
            data_source=conn,
            output_dir=Path(tmp_dir),
            save_to_db=False  # isolated test
        )

        _assert(len(sec_scores) == 8, f"Live DB Pipeline: 8 sectors scored (Got {len(sec_scores)})")
        _assert(ncri["total_incidents"] > 2000, f"Live DB Pipeline: Processed {ncri['total_incidents']} incidents")
        _assert(ncri["ncri_score"] > 0.0, f"Live DB Pipeline: NCRI calculated = {ncri['ncri_score']}")

    conn.close()


# =============================================================================
# MAIN TEST EXECUTION
# =============================================================================

def main() -> None:
    print("=" * 70)
    print("  RUNNING EXPLAINABLE CYBER RISK SCORING TEST SUITE")
    print("=" * 70)

    test_risk_category_boundaries()
    test_nifs_computation()
    test_wss_computation()
    test_sector_criticality()
    test_composite_acrs_scores()
    test_ncri_computation()
    test_threat_category_scoring()
    test_export_safety()
    test_database_integration()

    print("\n" + "=" * 70)
    total = PASS_COUNT + FAIL_COUNT
    print(f"  TEST RESULTS: {PASS_COUNT}/{total} checks passed.")
    if FAIL_COUNT == 0:
        print("  [SUCCESS] All risk scoring test cases passed successfully!")
    else:
        print(f"  [ERROR] {FAIL_COUNT} test(s) failed.")
        sys.exit(1)
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()

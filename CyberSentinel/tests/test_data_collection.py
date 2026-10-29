"""
tests/test_data_collection.py — Data Collection Validation Tests
=================================================================
National Cyber Threat Intelligence & Risk Analytics Platform

PURPOSE:
    This script validates that the data collection pipeline in
    src/collect_data.py works correctly, including:
      1. Module import check
      2. Output file presence (after collection run)
      3. CSV structure validation (mandatory columns present)
      4. File size sanity check (not empty or truncated)
      5. Data-source labelling (PUBLIC vs SYNTHETIC)
      6. Date range sanity (no future dates)
      7. Synthetic data label integrity (every SYNTHETIC row labelled)

IMPORTANT:
    Run src/collect_data.py FIRST to download the data, then run this test.
    You can run both together:

        cd CyberSentinel
        venv\\Scripts\\activate
        python -m src.collect_data --skip-nvd     # quick test without NVD
        python tests/test_data_collection.py

    Or collect everything (needs internet):
        python -m src.collect_data
        python tests/test_data_collection.py
"""

import sys
from pathlib import Path
from datetime import date

import pandas as pd

# =============================================================================
# SETUP — Add project root to sys.path so we can import src modules
# =============================================================================

PROJECT_ROOT  = Path(__file__).resolve().parent.parent
RAW_DIR       = PROJECT_ROOT / "data" / "raw"
SYNTHETIC_DIR = PROJECT_ROOT / "data" / "synthetic"

sys.path.insert(0, str(PROJECT_ROOT))

# =============================================================================
# TEST HELPERS
# =============================================================================

PASS_COUNT = 0
FAIL_COUNT = 0
SKIP_COUNT = 0


def _pass(label: str) -> None:
    global PASS_COUNT
    PASS_COUNT += 1
    print(f"  [PASS]  {label}")


def _fail(label: str, detail: str = "") -> None:
    global FAIL_COUNT
    FAIL_COUNT += 1
    msg = f"  [FAIL]  {label}"
    if detail:
        msg += f"\n           Detail: {detail}"
    print(msg)


def _skip(label: str, reason: str = "") -> None:
    global SKIP_COUNT
    SKIP_COUNT += 1
    msg = f"  [SKIP]  {label}"
    if reason:
        msg += f" ({reason})"
    print(msg)


def _section(title: str) -> None:
    print()
    print(f"  -- {title} " + "-" * (55 - len(title)))


# =============================================================================
# TEST 1 — Module Import
# =============================================================================

_section("Module Import")

try:
    from src.collect_data import (
        collect_all,
        collect_cisa_kev,
        collect_nvd_cve,
        generate_india_synthetic_incidents,
        _parse_nvd_cve_record,
        _validate_download,
    )
    _pass("src.collect_data imported successfully")
except ImportError as exc:
    _fail("src.collect_data import failed", str(exc))
    print()
    print("  [STOP] Cannot continue without the module. Fix the import error first.")
    sys.exit(1)


# =============================================================================
# TEST 2 — _validate_download helper (unit test, no files needed)
# =============================================================================

_section("_validate_download Helper Unit Tests")

import tempfile, os

with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tf:
    tf.write(b"a,b,c\n1,2,3\n")
    tmp_path = Path(tf.name)

try:
    result = _validate_download(tmp_path, min_bytes=1)
    if result:
        _pass("_validate_download returns True for valid file")
    else:
        _fail("_validate_download returned False for valid file")

    result_small = _validate_download(tmp_path, min_bytes=100_000)
    if not result_small:
        _pass("_validate_download returns False when file too small")
    else:
        _fail("_validate_download should return False for very high min_bytes threshold")
finally:
    os.unlink(tmp_path)

missing_path = Path("does_not_exist_xyz.csv")
if not _validate_download(missing_path):
    _pass("_validate_download returns False for missing file")
else:
    _fail("_validate_download should return False for missing file")


# =============================================================================
# TEST 3 — _parse_nvd_cve_record helper (unit test, no network needed)
# =============================================================================

_section("_parse_nvd_cve_record Parser Unit Tests")

# Minimal realistic NVD API response structure
sample_nvd_record = {
    "cve": {
        "id": "CVE-2024-12345",
        "published": "2024-06-01T12:00:00.000",
        "lastModified": "2024-06-15T08:30:00.000",
        "descriptions": [
            {"lang": "en", "value": "A test vulnerability in Example Software."},
            {"lang": "es", "value": "Una vulnerabilidad de prueba."},
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 8.1,
                        "baseSeverity": "HIGH",
                        "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                }
            ]
        },
        "weaknesses": [
            {"description": [{"lang": "en", "value": "CWE-79"}]},
            {"description": [{"lang": "en", "value": "CWE-89"}]},
        ],
    }
}

try:
    parsed = _parse_nvd_cve_record(sample_nvd_record)

    if parsed.get("cve_id") == "CVE-2024-12345":
        _pass("CVE ID parsed correctly")
    else:
        _fail("CVE ID parsing", f"Got: {parsed.get('cve_id')}")

    if parsed.get("published_date") == "2024-06-01":
        _pass("Publication date trimmed to YYYY-MM-DD")
    else:
        _fail("Publication date", f"Got: {parsed.get('published_date')}")

    if parsed.get("cvss_base_score") == 8.1:
        _pass("CVSS base score extracted correctly (8.1)")
    else:
        _fail("CVSS base score", f"Got: {parsed.get('cvss_base_score')}")

    if parsed.get("cvss_severity") == "HIGH":
        _pass("CVSS severity extracted correctly (HIGH)")
    else:
        _fail("CVSS severity", f"Got: {parsed.get('cvss_severity')}")

    cwe_ids = parsed.get("cwe_ids", "")
    if "CWE-79" in cwe_ids and "CWE-89" in cwe_ids:
        _pass("CWE IDs extracted and joined correctly")
    else:
        _fail("CWE IDs", f"Got: {cwe_ids}")

    if parsed.get("data_source") == "PUBLIC":
        _pass("data_source = PUBLIC for NVD records")
    else:
        _fail("data_source for NVD records", f"Got: {parsed.get('data_source')}")

    # English-only description test
    if "test vulnerability" in parsed.get("description", "").lower():
        _pass("English description extracted (non-English ignored)")
    else:
        _fail("Description extraction", f"Got: {parsed.get('description')}")

except Exception as exc:
    _fail("_parse_nvd_cve_record raised an exception", str(exc))


# =============================================================================
# TEST 4 — CISA KEV File Validation (file must already exist)
# =============================================================================

_section("CISA KEV Downloaded File Validation")

KEV_PATH = RAW_DIR / "cisa_kev.csv"

if not KEV_PATH.exists():
    _skip("CISA KEV file checks",
          "cisa_kev.csv not found. Run: python -m src.collect_data")
else:
    try:
        df_kev = pd.read_csv(KEV_PATH, encoding="utf-8")

        # 4a — Not empty
        if len(df_kev) > 0:
            _pass(f"CISA KEV file has {len(df_kev):,} records (non-empty)")
        else:
            _fail("CISA KEV file appears empty")

        # 4b — Required columns present
        required_kev_cols = ["cveID", "vulnerabilityName", "dateAdded",
                             "vendorProject", "product"]
        missing_cols = [c for c in required_kev_cols if c not in df_kev.columns]
        if not missing_cols:
            _pass(f"CISA KEV has all required columns: {required_kev_cols}")
        else:
            _fail("CISA KEV missing expected columns", str(missing_cols))

        # 4c — CVE IDs look like CVE-YYYY-NNNNN
        sample_ids = df_kev["cveID"].dropna().head(5).tolist()
        cve_id_ok = all(str(x).startswith("CVE-") for x in sample_ids)
        if cve_id_ok:
            _pass(f"CVE IDs look correct (sample: {sample_ids[0]})")
        else:
            _fail("CVE IDs may be malformed", str(sample_ids))

        # 4d — dateAdded is parseable
        try:
            dates_parsed = pd.to_datetime(df_kev["dateAdded"], errors="coerce")
            bad_dates = dates_parsed.isna().sum()
            if bad_dates == 0:
                _pass("All dateAdded values are valid dates")
            else:
                _fail(f"{bad_dates} unparseable dateAdded values in KEV file")
        except Exception as exc:
            _fail("dateAdded parse failed", str(exc))

        # 4e — No future dates in dateAdded
        today = date.today()
        max_date = pd.to_datetime(df_kev["dateAdded"], errors="coerce").max()
        if pd.notna(max_date) and max_date.date() <= today:
            _pass(f"Latest KEV date is not in the future ({max_date.date()})")
        else:
            _fail("KEV contains future dateAdded values", str(max_date))

    except Exception as exc:
        _fail("Failed to read or validate cisa_kev.csv", str(exc))


# =============================================================================
# TEST 5 — NVD CVE File Validation (file must already exist)
# =============================================================================

_section("NVD CVE Downloaded File Validation")

NVD_PATH = RAW_DIR / "nvd_cve.csv"

if not NVD_PATH.exists():
    _skip("NVD CVE file checks",
          "nvd_cve.csv not found. Run: python -m src.collect_data")
else:
    try:
        df_nvd = pd.read_csv(NVD_PATH, encoding="utf-8")

        # 5a — Not empty
        if len(df_nvd) > 0:
            _pass(f"NVD CVE file has {len(df_nvd):,} records (non-empty)")
        else:
            _fail("NVD CVE file appears empty")

        # 5b — Mandatory columns from taxonomy.json
        required_nvd_cols = ["cve_id", "published_date",
                              "cvss_base_score", "cvss_severity", "data_source"]
        missing_cols = [c for c in required_nvd_cols if c not in df_nvd.columns]
        if not missing_cols:
            _pass(f"NVD CVE has all required columns: {required_nvd_cols}")
        else:
            _fail("NVD CVE missing expected columns", str(missing_cols))

        # 5c — data_source = PUBLIC on every row
        if "data_source" in df_nvd.columns:
            non_public = df_nvd[df_nvd["data_source"] != "PUBLIC"]
            if len(non_public) == 0:
                _pass("All NVD records labelled data_source = PUBLIC")
            else:
                _fail(f"{len(non_public)} NVD rows have unexpected data_source value",
                      str(df_nvd["data_source"].unique()))

        # 5d — CVSS score range 0.0 – 10.0
        if "cvss_base_score" in df_nvd.columns:
            scores = df_nvd["cvss_base_score"].dropna().astype(float)
            if len(scores) > 0:
                out_of_range = scores[(scores < 0) | (scores > 10)]
                if len(out_of_range) == 0:
                    _pass(f"All CVSS scores are in range 0–10 (sample min: {scores.min():.1f}, max: {scores.max():.1f})")
                else:
                    _fail(f"{len(out_of_range)} CVSS scores are outside 0–10 range")
            else:
                _skip("CVSS score range check", "No non-null CVSS scores found")

        # 5e — published_date parseable
        if "published_date" in df_nvd.columns:
            try:
                dates = pd.to_datetime(df_nvd["published_date"], errors="coerce")
                bad = dates.isna().sum()
                if bad == 0:
                    _pass("All published_date values are valid dates")
                else:
                    _fail(f"{bad} unparseable published_date values in NVD file")
            except Exception as exc:
                _fail("published_date parse failed", str(exc))

    except Exception as exc:
        _fail("Failed to read or validate nvd_cve.csv", str(exc))


# =============================================================================
# TEST 6 — India Synthetic Incident File Validation
# =============================================================================

_section("India Synthetic Incident File Validation")

SYN_PATH = SYNTHETIC_DIR / "synthetic_india_incidents.csv"

if not SYN_PATH.exists():
    _skip("Synthetic incidents file checks",
          "File not found. Run: python -m src.collect_data --skip-kev --skip-nvd")
else:
    try:
        df_syn = pd.read_csv(SYN_PATH, encoding="utf-8")

        # 6a — Not empty
        if len(df_syn) > 0:
            _pass(f"Synthetic file has {len(df_syn):,} records (non-empty)")
        else:
            _fail("Synthetic incidents file appears empty")

        # 6b — All required incident columns present
        required_syn_cols = ["incident_id", "incident_date", "threat_type",
                              "target_sector", "severity", "target_state",
                              "data_source", "synthetic_basis"]
        missing_cols = [c for c in required_syn_cols if c not in df_syn.columns]
        if not missing_cols:
            _pass(f"Synthetic file has all required columns: {required_syn_cols}")
        else:
            _fail("Synthetic file missing expected columns", str(missing_cols))

        # 6c — EVERY row must be labelled SYNTHETIC
        if "data_source" in df_syn.columns:
            non_synthetic = df_syn[df_syn["data_source"] != "SYNTHETIC"]
            if len(non_synthetic) == 0:
                _pass("All synthetic rows correctly labelled data_source = SYNTHETIC")
            else:
                _fail(
                    f"{len(non_synthetic)} synthetic rows NOT labelled SYNTHETIC — "
                    "DATA INTEGRITY ERROR",
                    str(df_syn["data_source"].unique())
                )

        # 6d — synthetic_basis column present and non-empty
        if "synthetic_basis" in df_syn.columns:
            empty_basis = df_syn["synthetic_basis"].isna().sum()
            if empty_basis == 0:
                basis_value = df_syn["synthetic_basis"].iloc[0]
                _pass(f"synthetic_basis field present on all rows: '{basis_value}'")
            else:
                _fail(f"{empty_basis} rows have empty synthetic_basis field")

        # 6e — threat_type values from taxonomy
        valid_threat_types = {
            "Ransomware", "Phishing", "DDoS", "Data Breach", "Malware",
            "SQL Injection", "Zero-Day Exploit", "Supply Chain Attack",
            "Insider Threat", "Social Engineering", "Other"
        }
        if "threat_type" in df_syn.columns:
            unknown_threats = df_syn[~df_syn["threat_type"].isin(valid_threat_types)]["threat_type"].unique()
            if len(unknown_threats) == 0:
                _pass("All threat_type values are from the taxonomy vocabulary")
            else:
                _fail("Unknown threat_type values found", str(unknown_threats))

        # 6f — Severity values valid
        valid_severities = {"Critical", "High", "Medium", "Low", "Unknown"}
        if "severity" in df_syn.columns:
            bad_sev = df_syn[~df_syn["severity"].isin(valid_severities)]["severity"].unique()
            if len(bad_sev) == 0:
                _pass("All severity values are valid (Critical/High/Medium/Low/Unknown)")
            else:
                _fail("Invalid severity values found", str(bad_sev))

        # 6g — Date range 2021 – 2024
        if "incident_date" in df_syn.columns:
            dates = pd.to_datetime(df_syn["incident_date"], errors="coerce")
            years = dates.dropna().dt.year.unique()
            years_sorted = sorted(years)
            if set(years_sorted) == {2021, 2022, 2023, 2024}:
                _pass(f"Synthetic incidents cover years 2021–2024: {years_sorted}")
            else:
                _fail(f"Unexpected year range", str(years_sorted))

        # 6h — No duplicate incident_id
        if "incident_id" in df_syn.columns:
            dups = df_syn["incident_id"].duplicated().sum()
            if dups == 0:
                _pass("No duplicate incident_id values")
            else:
                _fail(f"{dups} duplicate incident_id values found")

    except Exception as exc:
        _fail("Failed to read or validate synthetic incidents file", str(exc))


# =============================================================================
# TEST 7 — collect_all import works (not a live call)
# =============================================================================

_section("API Function Signatures")

import inspect

for fn_name, fn_obj in [
    ("collect_all", collect_all),
    ("collect_cisa_kev", collect_cisa_kev),
    ("collect_nvd_cve", collect_nvd_cve),
    ("generate_india_synthetic_incidents", generate_india_synthetic_incidents),
]:
    sig = inspect.signature(fn_obj)
    _pass(f"Function {fn_name}() defined with params: {list(sig.parameters.keys())}")


# =============================================================================
# FINAL SUMMARY
# =============================================================================

print()
print("-" * 60)
total = PASS_COUNT + FAIL_COUNT + SKIP_COUNT

print(f"  Results: {PASS_COUNT} passed  /  {FAIL_COUNT} failed  /  {SKIP_COUNT} skipped  (total {total})")
print()

if FAIL_COUNT == 0:
    print("  [DONE] All checks passed or skipped.")
    print()
    if SKIP_COUNT > 0:
        print("  Note: Skipped tests require running data collection first.")
        print("  To collect real data, run:")
        print("    python -m src.collect_data")
        print("  For offline/quick test (synthetic only):")
        print("    python -m src.collect_data --skip-kev --skip-nvd")
else:
    print(f"  [FAIL] {FAIL_COUNT} test(s) failed. See details above.")
    sys.exit(1)

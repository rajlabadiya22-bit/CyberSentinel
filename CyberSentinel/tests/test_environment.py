"""
tests/test_environment.py — Environment Verification Tests
============================================================
National Cyber Threat Intelligence & Risk Analytics Platform

PURPOSE:
    Run this script FIRST after setting up the project to verify that
    your Python environment is correctly configured.

HOW TO RUN:
    python tests/test_environment.py

WHAT IT CHECKS:
    1. Python version (must be 3.10 or higher)
    2. pandas is installed and importable
    3. numpy is installed and importable
    4. sqlite3 is available (built into Python — should always pass)
    5. openpyxl is installed (needed for Excel file support)
    6. The config/taxonomy.json file exists and can be parsed
    7. The database/schema.sql file exists
    8. The classify_risk_category() function returns the correct labels
    9. The validate_acrs_range() function works correctly

EXPECTED OUTPUT (all tests passing):
    [PASS] Python version: 3.x.x
    [PASS] pandas 2.x.x imported successfully
    [PASS] numpy 1.x.x imported successfully
    [PASS] sqlite3 imported successfully (built-in)
    [PASS] openpyxl imported successfully
    [PASS] taxonomy.json found and valid JSON
    [PASS] schema.sql found
    [PASS] classify_risk_category(82.5) = 'Critical Risk'
    [PASS] classify_risk_category(55.0) = 'High Risk'
    [PASS] classify_risk_category(30.0) = 'Moderate Risk'
    [PASS] classify_risk_category(10.0) = 'Low Risk'
    [PASS] validate_acrs_range(0.0) = True
    [PASS] validate_acrs_range(100.0) = True
    [PASS] validate_acrs_range(150.0) = False
    ──────────────────────────────────────────────
    ✅ All 14 checks passed! Your environment is ready.
"""

import sys
import json
from pathlib import Path


# =============================================================================
# TEST HELPERS
# =============================================================================

PASS_COUNT = 0
FAIL_COUNT = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    """Print a PASS or FAIL result for a single check."""
    global PASS_COUNT, FAIL_COUNT
    status = "[PASS]" if condition else "[FAIL]"
    message = f"{status} {label}"
    if detail:
        message += f": {detail}"
    print(message)
    if condition:
        PASS_COUNT += 1
    else:
        FAIL_COUNT += 1


# =============================================================================
# FIND THE PROJECT ROOT
# This ensures the tests work whether you run from CyberSentinel/ or tests/.
# =============================================================================

# The tests/ folder is one level below the project root.
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# =============================================================================
# TEST 1: PYTHON VERSION
# =============================================================================

python_version = sys.version_info
is_python_ok = python_version >= (3, 10)
version_string = f"{python_version.major}.{python_version.minor}.{python_version.micro}"
check(
    f"Python version: {version_string}",
    is_python_ok,
    "" if is_python_ok else "FAIL: Requires Python 3.10 or higher. Please upgrade."
)


# =============================================================================
# TEST 2: PANDAS
# =============================================================================

try:
    import pandas as pd
    check(f"pandas {pd.__version__} imported successfully", True)
except ImportError:
    check("pandas import", False, "Run: pip install -r requirements.txt")


# =============================================================================
# TEST 3: NUMPY
# =============================================================================

try:
    import numpy as np
    check(f"numpy {np.__version__} imported successfully", True)
except ImportError:
    check("numpy import", False, "Run: pip install -r requirements.txt")


# =============================================================================
# TEST 4: SQLITE3 (built-in — should always pass)
# =============================================================================

try:
    import sqlite3
    check("sqlite3 imported successfully (built-in)", True)
except ImportError:
    check("sqlite3 import", False, "This is a Python built-in — check your Python installation.")


# =============================================================================
# TEST 5: OPENPYXL (needed for reading Excel files)
# =============================================================================

try:
    import openpyxl
    check("openpyxl imported successfully", True)
except ImportError:
    check("openpyxl import", False, "Run: pip install openpyxl")


# =============================================================================
# TEST 6: TAXONOMY.JSON EXISTS AND IS VALID JSON
# =============================================================================

taxonomy_path = PROJECT_ROOT / "config" / "taxonomy.json"
if taxonomy_path.exists():
    try:
        with open(taxonomy_path, "r", encoding="utf-8") as f:
            taxonomy = json.load(f)
        check("taxonomy.json found and valid JSON", True)

        # Also check it has the required keys
        required_keys = ["threat_types", "target_sectors", "sector_criticality_weights",
                         "mandatory_incident_columns"]
        for key in required_keys:
            check(f"  taxonomy.json contains key: '{key}'", key in taxonomy)

    except json.JSONDecodeError as e:
        check("taxonomy.json is valid JSON", False, f"JSON error: {e}")
else:
    check("taxonomy.json found", False, f"File not found at: {taxonomy_path}")


# =============================================================================
# TEST 7: SCHEMA.SQL EXISTS
# =============================================================================

schema_path = PROJECT_ROOT / "database" / "schema.sql"
check("schema.sql found", schema_path.exists(),
      "" if schema_path.exists() else f"File not found at: {schema_path}")


# =============================================================================
# TEST 8: RISK SCORING FUNCTIONS (these are implemented in risk_scoring.py)
# =============================================================================

try:
    from src.risk_scoring import classify_risk_category, validate_acrs_range

    # Test classify_risk_category
    check("classify_risk_category(82.5) = 'Critical Risk'",
          classify_risk_category(82.5) == "Critical Risk")
    check("classify_risk_category(55.0) = 'High Risk'",
          classify_risk_category(55.0) == "High Risk")
    check("classify_risk_category(30.0) = 'Moderate Risk'",
          classify_risk_category(30.0) == "Moderate Risk")
    check("classify_risk_category(10.0) = 'Low Risk'",
          classify_risk_category(10.0) == "Low Risk")

    # Test validate_acrs_range
    check("validate_acrs_range(0.0) = True",
          validate_acrs_range(0.0) is True)
    check("validate_acrs_range(100.0) = True",
          validate_acrs_range(100.0) is True)
    check("validate_acrs_range(150.0) = False",
          validate_acrs_range(150.0) is False)

except ImportError as e:
    check("Import from src.risk_scoring", False, str(e))


# =============================================================================
# TEST 9: SQLITE3 CAN CREATE AN IN-MEMORY DATABASE
# =============================================================================

try:
    import sqlite3
    conn = sqlite3.connect(":memory:")   # In-memory database (no file created)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT)")
    cursor.execute("INSERT INTO test_table (name) VALUES (?)", ("test_record",))
    conn.commit()
    cursor.execute("SELECT name FROM test_table WHERE id = 1")
    result = cursor.fetchone()
    conn.close()
    check("SQLite in-memory database works", result[0] == "test_record")
except Exception as e:
    check("SQLite in-memory database", False, str(e))


# =============================================================================
# FINAL SUMMARY
# =============================================================================

print()
print("-" * 50)
total = PASS_COUNT + FAIL_COUNT

if FAIL_COUNT == 0:
    print(f"[DONE] All {PASS_COUNT} checks passed! Your environment is ready.")
    print()
    print("Next step:")
    print("  Place your incident CSV in data/raw/ and run:")
    print("  python main.py --input data/raw/incidents.csv")
    print()
    print("  Or use the synthetic demo data:")
    print("  python main.py --input data/synthetic/synthetic_incidents.csv")
else:
    print(f"[FAIL] {FAIL_COUNT} of {total} checks FAILED. Please fix the issues above.")
    print()
    print("Common fix: Make sure you ran 'pip install -r requirements.txt'")
    print("with your virtual environment activated.")
    sys.exit(1)

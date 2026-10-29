"""
src/cleaning.py — Data Cleaning and Preprocessing Module
==========================================================
National Cyber Threat Intelligence & Risk Analytics Platform

PURPOSE:
    This module takes the RAW data loaded by ingestion.py and makes it
    clean, consistent, and ready for storage in the database.

    Think of this as a "quality control" step — it fixes problems in the
    data before any analysis is done.

WHAT THIS MODULE DOES:
    1. Remove duplicate records.
    2. Standardise date fields to ISO 8601 format (YYYY-MM-DD).
    3. Map threat types and sector names to the controlled vocabulary
       defined in config/taxonomy.json.
    4. Handle missing (null/NaN) values.
    5. Generate a preprocessing summary report.

WHAT THIS MODULE DOES NOT DO:
    - It does NOT read files (that is ingestion.py's job).
    - It does NOT write to the database.
    - It does NOT compute risk scores.

KEY DESIGN PRINCIPLE:
    If a record has a bad date   → EXCLUDE it and LOG a warning.
    If a record has a bad category → MAP it to "Other" and LOG a warning.
    If a record is missing an optional field → FILL with sentinel value and KEEP it.
    NEVER silently drop data without logging.

SRS REFERENCES:
    FR-007 (identify duplicates), FR-008 (remove duplicates),
    FR-009 (standardise dates), FR-010 (map taxonomy),
    FR-011 (handle missing values), FR-012 (preprocessing report),
    FR-013 (normalise numeric units), NFR-004 (graceful error handling)
"""

import logging
from pathlib import Path
from datetime import datetime

import pandas as pd
import numpy as np


# =============================================================================
# MODULE CONSTANTS
# =============================================================================

# The composite key used to detect duplicate incident records.
# A duplicate is a row where ALL of these columns have the same value.
DUPLICATE_KEY_COLUMNS = ["incident_date", "threat_type", "target_sector"]

# Sentinel values for missing optional fields (distinct from zero or empty string)
MISSING_STRING_SENTINEL  = "Unknown"   # for text columns (e.g., target_state)
MISSING_NUMERIC_SENTINEL = -1          # for numeric columns (e.g., resolution_days)

# Optional incident columns that may or may not be in the source file
OPTIONAL_STRING_COLUMNS  = ["target_state", "description"]
OPTIONAL_NUMERIC_COLUMNS = ["financial_loss_inr", "resolution_days"]

# CVE severity normalisation map (NVD returns uppercase; our DB uses Title Case)
CVSS_SEVERITY_NORMALISE = {
    "CRITICAL": "Critical",
    "HIGH"    : "High",
    "MEDIUM"  : "Medium",
    "LOW"     : "Low",
    "NONE"    : "Low",      # CVSS v3 "NONE" maps to Low for storage
    "UNKNOWN" : "Unknown",
}


# =============================================================================
# MAIN CLEANING FUNCTION — INCIDENT DATA
# =============================================================================

def clean_incident_data(raw_df: pd.DataFrame, taxonomy: dict) -> tuple:
    """
    Run all cleaning steps on the raw incident DataFrame.

    This is the main function called by main.py. It calls each cleaning
    step in order and returns a cleaned DataFrame plus a summary report.

    Steps performed (in order):
        1. Copy raw data so the original is never modified.
        2. Remove duplicate rows (based on DUPLICATE_KEY_COLUMNS).
        3. Standardise incident_date to YYYY-MM-DD; exclude rows with bad dates.
        4. Map threat_type, target_sector, severity to taxonomy vocabulary.
        5. Fill missing optional fields with sentinel values.

    Args:
        raw_df (pd.DataFrame): The raw DataFrame from ingestion.py.
        taxonomy (dict): The taxonomy configuration from taxonomy.json.

    Returns:
        tuple: (cleaned_df, cleaning_report)
            cleaned_df (pd.DataFrame): Cleaned and validated DataFrame.
            cleaning_report (dict): Summary of what cleaning changed, e.g.:
                {
                    "original_count"          : 2500,
                    "duplicates_removed"      : 12,
                    "bad_dates_excluded"      : 3,
                    "categories_mapped"       : 8,
                    "missing_values_filled"   : 450,
                    "final_count"             : 2485,
                }
    """
    logging.info("Starting incident data cleaning pipeline...")
    df = raw_df.copy()

    original_count = len(df)
    logging.info(f"  Input rows: {original_count:,}")

    # Step 1: Remove duplicate rows
    df, dup_count = remove_duplicates(df)

    # Step 2: Standardise dates
    df, bad_date_count = standardise_dates(df, date_column="incident_date")

    # Step 3: Map categorical values to controlled vocabulary
    df, mapped_count = map_taxonomy_values(df, taxonomy)

    # Step 4: Fill missing optional fields
    df, filled_count = handle_missing_values(df)

    final_count = len(df)
    logging.info(f"  Output rows: {final_count:,}")

    # Build and return the report
    report = build_cleaning_report(
        original_count, dup_count, bad_date_count, mapped_count,
        filled_count, final_count
    )
    return df, report


# =============================================================================
# MAIN CLEANING FUNCTION — CVE DATA
# =============================================================================

def clean_cve_data(raw_df: pd.DataFrame) -> tuple:
    """
    Run all cleaning steps on the raw CVE DataFrame (NVD or CISA KEV).

    Steps performed:
        1. Remove duplicate CVEs (based on cve_id).
        2. Standardise published_date to YYYY-MM-DD.
        3. Normalise cvss_severity to Title Case (Critical / High / Medium / Low).
        4. Fill missing cvss_base_score with 0.0 and mark severity as "Unknown".
        5. Cap description length at 500 characters.

    Args:
        raw_df (pd.DataFrame): The raw CVE DataFrame from ingestion.py.

    Returns:
        tuple: (cleaned_df, cleaning_report)
    """
    logging.info("Starting CVE data cleaning pipeline...")
    df = raw_df.copy()

    original_count = len(df)
    logging.info(f"  Input CVE rows: {original_count:,}")

    # Step 1: Drop duplicate CVE IDs (keep first occurrence)
    if "cve_id" in df.columns:
        count_before = len(df)
        df = df.drop_duplicates(subset=["cve_id"], keep="first")
        dup_count = count_before - len(df)
        if dup_count:
            logging.info(f"  Removed {dup_count:,} duplicate CVE IDs.")
    else:
        dup_count = 0

    # Step 2: Standardise published_date
    df, bad_date_count = standardise_dates(df, date_column="published_date")

    # Step 3: Normalise cvss_severity to Title Case
    if "cvss_severity" in df.columns:
        df["cvss_severity"] = (
            df["cvss_severity"]
            .fillna("Unknown")
            .str.strip()
            .str.upper()
            .map(CVSS_SEVERITY_NORMALISE)
            .fillna("Unknown")
        )
        logging.info(
            f"  CVSS severity distribution after normalisation:\n"
            f"  {df['cvss_severity'].value_counts().to_dict()}"
        )

    # Step 4: Handle missing CVSS score
    if "cvss_base_score" in df.columns:
        null_scores = df["cvss_base_score"].isna().sum()
        if null_scores:
            df.loc[df["cvss_base_score"].isna(), "cvss_severity"]    = "Unknown"
            df["cvss_base_score"] = df["cvss_base_score"].fillna(0.0)
            logging.info(
                f"  Filled {null_scores:,} missing CVSS scores with 0.0 "
                f"and set severity to 'Unknown'."
            )

    # Step 5: Cap description length
    if "description" in df.columns:
        df["description"] = df["description"].fillna("").str[:500]

    # Ensure data_source is labelled
    if "data_source" not in df.columns:
        df["data_source"] = "PUBLIC"

    final_count = len(df)
    logging.info(f"  Output CVE rows: {final_count:,}")

    report = {
        "original_count"    : original_count,
        "duplicates_removed": dup_count,
        "bad_dates_excluded": bad_date_count,
        "final_count"       : final_count,
        "records_lost"      : original_count - final_count,
        "cleaning_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    return df, report


# =============================================================================
# INDIVIDUAL CLEANING STEPS (called by clean_incident_data above)
# =============================================================================

def remove_duplicates(df: pd.DataFrame) -> tuple:
    """
    Identify and remove duplicate rows from the incident DataFrame.

    A "duplicate" is defined as a row where the values in
    DUPLICATE_KEY_COLUMNS (incident_date + threat_type + target_sector)
    are all identical to another row.

    When duplicates are found:
        - Keep the FIRST occurrence.
        - Remove all subsequent occurrences.
        - Log how many were removed.

    Args:
        df (pd.DataFrame): Input DataFrame.

    Returns:
        tuple: (cleaned_df, count_removed)
            cleaned_df: DataFrame with duplicates removed.
            count_removed (int): Number of rows removed.
    """
    count_before = len(df)

    # Only apply if all key columns exist; otherwise skip this step
    existing_keys = [c for c in DUPLICATE_KEY_COLUMNS if c in df.columns]
    if len(existing_keys) < len(DUPLICATE_KEY_COLUMNS):
        logging.warning(
            f"  Duplicate check skipped: not all key columns found. "
            f"Found: {existing_keys}, needed: {DUPLICATE_KEY_COLUMNS}"
        )
        return df, 0

    df = df.drop_duplicates(subset=existing_keys, keep="first").reset_index(drop=True)
    count_removed = count_before - len(df)

    if count_removed > 0:
        logging.info(f"  Removed {count_removed:,} duplicate records.")
    else:
        logging.info("  No duplicate records found.")

    return df, count_removed


def standardise_dates(df: pd.DataFrame, date_column: str = "incident_date") -> tuple:
    """
    Convert all date values in the given column to ISO 8601 format (YYYY-MM-DD).

    Pandas can automatically parse many date formats (DD/MM/YYYY, MM-DD-YYYY,
    ISO format, etc.).

    Records where the date CANNOT be parsed are EXCLUDED and logged as warnings.

    Args:
        df (pd.DataFrame): Input DataFrame.
        date_column (str): Name of the column containing dates.

    Returns:
        tuple: (cleaned_df, count_excluded)
            cleaned_df: DataFrame with standardised dates (bad rows removed).
            count_excluded (int): Number of rows excluded due to bad dates.
    """
    if date_column not in df.columns:
        logging.warning(
            f"  Date standardisation skipped: column '{date_column}' not found."
        )
        return df, 0

    # Convert dates; invalid values become NaT (Not a Time)
    df[date_column] = pd.to_datetime(
        df[date_column],
        errors="coerce",
        dayfirst=False,       # Prefer YYYY-MM-DD interpretation
    )

    # Count and log rows with bad dates
    bad_mask      = df[date_column].isna()
    count_excluded = int(bad_mask.sum())

    if count_excluded > 0:
        logging.warning(
            f"  Excluding {count_excluded:,} records with unparseable "
            f"'{date_column}' values."
        )
        df = df[~bad_mask].copy()

    # Convert datetime back to "YYYY-MM-DD" string format for the database
    df[date_column] = df[date_column].dt.strftime("%Y-%m-%d")

    logging.info(
        f"  Date standardisation complete for '{date_column}'. "
        f"{len(df):,} records retained."
    )
    return df, count_excluded


def map_taxonomy_values(df: pd.DataFrame, taxonomy: dict) -> tuple:
    """
    Map the values in threat_type, target_sector, and severity columns to the
    controlled vocabulary defined in config/taxonomy.json.

    If a value in the CSV is NOT in the controlled vocabulary:
        - Replace it with "Other" (for threat_type / target_sector).
        - Replace it with "Unknown" (for severity).
        - Log a warning so the developer knows about the unmapped value.

    Args:
        df (pd.DataFrame): Input DataFrame.
        taxonomy (dict): Loaded taxonomy configuration.

    Returns:
        tuple: (cleaned_df, count_mapped_to_other)
            cleaned_df: DataFrame with normalised category values.
            count_mapped_to_other (int): Total number of values remapped.
    """
    valid_threat_types = set(taxonomy.get("threat_types", []))
    valid_sectors      = set(taxonomy.get("target_sectors", []))
    valid_severities   = set(taxonomy.get("severity_levels", {}).keys())

    count_remapped = 0

    # ── threat_type ───────────────────────────────────────────────────────────
    if "threat_type" in df.columns and valid_threat_types:
        # Standardise capitalisation to Title Case first
        df["threat_type"] = df["threat_type"].astype(str).str.strip().str.title()
        bad_mask          = ~df["threat_type"].isin(valid_threat_types)
        bad_values        = df.loc[bad_mask, "threat_type"].unique().tolist()
        n_bad             = int(bad_mask.sum())
        if n_bad > 0:
            logging.warning(
                f"  Remapping {n_bad:,} threat_type values to 'Other': "
                f"{bad_values[:10]}"
            )
            df.loc[bad_mask, "threat_type"] = "Other"
            count_remapped += n_bad

    # ── target_sector ─────────────────────────────────────────────────────────
    if "target_sector" in df.columns and valid_sectors:
        df["target_sector"] = df["target_sector"].astype(str).str.strip()
        bad_mask            = ~df["target_sector"].isin(valid_sectors)
        bad_values          = df.loc[bad_mask, "target_sector"].unique().tolist()
        n_bad               = int(bad_mask.sum())
        if n_bad > 0:
            logging.warning(
                f"  Remapping {n_bad:,} target_sector values to 'Other': "
                f"{bad_values[:10]}"
            )
            df.loc[bad_mask, "target_sector"] = "Other"
            count_remapped += n_bad

    # ── severity ──────────────────────────────────────────────────────────────
    if "severity" in df.columns and valid_severities:
        df["severity"] = (
            df["severity"]
            .astype(str)
            .str.strip()
            .str.capitalize()
        )
        bad_mask   = ~df["severity"].isin(valid_severities)
        n_bad      = int(bad_mask.sum())
        if n_bad > 0:
            logging.warning(
                f"  Remapping {n_bad:,} severity values to 'Unknown'."
            )
            df.loc[bad_mask, "severity"] = "Unknown"
            count_remapped += n_bad

    if count_remapped == 0:
        logging.info("  Taxonomy mapping complete — all values already valid.")
    else:
        logging.info(
            f"  Taxonomy mapping complete — {count_remapped:,} values remapped."
        )

    return df, count_remapped


def handle_missing_values(df: pd.DataFrame) -> tuple:
    """
    Fill missing (NaN/None) values in optional columns with sentinel values.

    This preserves rows that have missing optional data rather than deleting
    them (which would lose valid information from mandatory fields).

    Sentinel values used:
        - String/text columns → "Unknown"
        - Numeric columns     → -1 (distinct from 0, means "no data available")

    Args:
        df (pd.DataFrame): Input DataFrame.

    Returns:
        tuple: (cleaned_df, count_filled)
            cleaned_df: DataFrame with nulls replaced by sentinel values.
            count_filled (int): Total number of individual cells filled.
    """
    count_filled = 0

    for col in OPTIONAL_STRING_COLUMNS:
        if col in df.columns:
            n = int(df[col].isna().sum())
            if n > 0:
                df[col] = df[col].fillna(MISSING_STRING_SENTINEL)
                count_filled += n
                logging.info(
                    f"  Filled {n:,} missing '{col}' values with "
                    f"'{MISSING_STRING_SENTINEL}'."
                )

    for col in OPTIONAL_NUMERIC_COLUMNS:
        if col in df.columns:
            n = int(df[col].isna().sum())
            if n > 0:
                df[col] = df[col].fillna(MISSING_NUMERIC_SENTINEL)
                count_filled += n
                logging.info(
                    f"  Filled {n:,} missing '{col}' values with "
                    f"{MISSING_NUMERIC_SENTINEL}."
                )

    if count_filled == 0:
        logging.info("  No missing values found in optional columns.")
    else:
        logging.info(f"  Total cells filled with sentinel values: {count_filled:,}")

    return df, count_filled


# =============================================================================
# REPORTING HELPER
# =============================================================================

def build_cleaning_report(
    original_count: int,
    dup_count: int,
    bad_date_count: int,
    mapped_count: int,
    filled_count: int,
    final_count: int,
) -> dict:
    """
    Build a dictionary summarising the cleaning results.

    Used by main.py to generate the preprocessing summary report
    (saved to output/reports/preprocessing_summary.csv).

    Args:
        original_count (int): Rows before cleaning.
        dup_count (int): Duplicate rows removed.
        bad_date_count (int): Rows excluded for bad dates.
        mapped_count (int): Values remapped to controlled vocabulary.
        filled_count (int): Missing cells filled with sentinel values.
        final_count (int): Rows after all cleaning.

    Returns:
        dict: A structured report dictionary.
    """
    return {
        "original_count"        : original_count,
        "duplicates_removed"    : dup_count,
        "bad_dates_excluded"    : bad_date_count,
        "categories_remapped"   : mapped_count,
        "missing_values_filled" : filled_count,
        "final_count"           : final_count,
        "records_lost"          : original_count - final_count,
        "retention_rate_pct"    : round(final_count / original_count * 100, 2)
                                  if original_count > 0 else 0.0,
        "cleaning_timestamp"    : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# =============================================================================
# UTILITY: Save cleaning report to CSV
# =============================================================================

def save_cleaning_report(report: dict, output_dir: Path) -> Path:
    """
    Save the cleaning report dictionary to a CSV file.

    Args:
        report (dict): The cleaning report from build_cleaning_report().
        output_dir (Path): Where to save the report CSV.

    Returns:
        Path: The path of the saved report file.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    report_path = output_dir / "preprocessing_summary.csv"

    # Convert the dict to a two-column DataFrame: Metric | Value
    rows = [{"metric": k, "value": v} for k, v in report.items()]
    pd.DataFrame(rows).to_csv(report_path, index=False, encoding="utf-8")

    logging.info(f"  Cleaning report saved to: {report_path}")
    return report_path

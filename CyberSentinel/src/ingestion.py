"""
src/ingestion.py — Data Ingestion Module
==========================================
National Cyber Threat Intelligence & Risk Analytics Platform

PURPOSE:
    This module is responsible for READING data from CSV and Excel files
    and VALIDATING that the input files have the required columns.

    Think of this as the "front door" of the pipeline — data comes in
    through this module before anything else happens to it.

WHAT THIS MODULE DOES:
    1. Read a CSV or Excel file into a Pandas DataFrame.
    2. Normalise column names (lowercase + strip whitespace) for consistency.
    3. Check that all mandatory columns are present.
    4. Log the import details (file name, row count, timestamp).
    5. Reject and skip files that are missing required columns.

WHAT THIS MODULE DOES NOT DO:
    - It does NOT clean or transform the data (that is cleaning.py's job).
    - It does NOT write to the database.
    - It does NOT compute any analytics.

SRS REFERENCES:
    FR-001 (accept CSV/Excel), FR-002 (accept CVE CSV/JSON),
    FR-003 (validate columns), FR-004 (batch import),
    FR-005 (log imports), FR-006 (tag synthetic data),
    NFR-004 (graceful error handling), NFR-007 (human-readable errors)
"""

import logging
from pathlib import Path
from datetime import datetime

import pandas as pd


# =============================================================================
# COLUMN NAME MAPPING — KEV → our internal schema
# =============================================================================
# The CISA KEV CSV uses its own column names (e.g. "cveID", "dateAdded").
# We map them to the column names the rest of our pipeline expects.
# This means you can use load_cve_csv() for KEV files too.

KEV_COLUMN_MAP = {
    "cveid"            : "cve_id",
    "vendorproject"    : "vendor",
    "product"          : "product",
    "vulnerabilityname": "vulnerability_name",
    "dateadded"        : "published_date",
    "shortdescription" : "description",
    "knownransomwarecampaignuse": "known_ransomware_use",
    "cwes"             : "cwe_ids",
}


# =============================================================================
# MAIN INGESTION FUNCTIONS
# =============================================================================

def load_incident_csv(filepath: Path, mandatory_columns: list) -> pd.DataFrame:
    """
    Read a cyber incident CSV (or Excel) file into a Pandas DataFrame.

    This function:
        1. Detects whether the file is CSV or Excel based on its extension.
        2. Reads all rows from the file.
        3. Normalises column names to lowercase with stripped whitespace.
        4. Calls validate_columns() to check required columns exist.
        5. Calls log_import() to record the import event.

    Args:
        filepath (Path): The full path to the input file.
        mandatory_columns (list): List of column names that MUST be present.
                                   Comes from taxonomy["mandatory_incident_columns"].

    Returns:
        pd.DataFrame: A DataFrame containing all rows from the file,
                      with column names normalised to lowercase.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file format is not supported (.csv or .xlsx).
        SystemExit: If mandatory columns are missing (logged + raises).

    Example:
        df = load_incident_csv(
            Path("data/raw/incidents.csv"),
            ["incident_id", "incident_date"]
        )
    """
    filepath = Path(filepath)
    logging.info(f"Loading incident file: {filepath.name}")

    if not filepath.exists():
        raise FileNotFoundError(
            f"Input file not found: {filepath}\n"
            f"Make sure the file exists in the data/raw/ folder."
        )

    suffix = filepath.suffix.lower()

    try:
        if suffix == ".csv":
            df = pd.read_csv(filepath, encoding="utf-8", low_memory=False)
        elif suffix in (".xlsx", ".xls"):
            df = pd.read_excel(filepath)
        else:
            raise ValueError(
                f"Unsupported file format: '{suffix}'. "
                f"Only .csv and .xlsx files are accepted."
            )
    except Exception as exc:
        logging.error(f"  [FAIL] Could not read {filepath.name}: {exc}")
        raise

    # Normalise column names: lowercase + strip surrounding spaces
    df.columns = df.columns.str.strip().str.lower()

    # Validate that required columns are present
    if not validate_columns(df, mandatory_columns):
        raise SystemExit(
            f"Ingestion halted for '{filepath.name}' because required columns "
            f"are missing. Check the error messages above."
        )

    # Log the successful import
    log_import(filepath, len(df))

    logging.info(
        f"  [OK] Loaded {len(df):,} rows from {filepath.name} "
        f"({len(df.columns)} columns)"
    )
    return df


def load_cve_csv(filepath: Path, mandatory_columns: list) -> pd.DataFrame:
    """
    Read a CVE/vulnerability dataset from a CSV file into a Pandas DataFrame.

    This function handles two CVE CSV formats:
        1. Our own NVD export (from src/collect_data.py): already has the correct
           column names (cve_id, published_date, cvss_base_score, cvss_severity).
        2. The CISA KEV direct download (cisa_kev.csv): uses different column
           names which are automatically remapped using KEV_COLUMN_MAP.

    The function auto-detects the format by checking whether the file has
    a "cveid" column (KEV format) or a "cve_id" column (NVD export format).

    Args:
        filepath (Path): Path to the downloaded CVE CSV file.
        mandatory_columns (list): List of required column names after mapping.
                                   From taxonomy["mandatory_cve_columns"].

    Returns:
        pd.DataFrame: A DataFrame with CVE records, columns in our schema format.

    Raises:
        FileNotFoundError: If the file does not exist.
        SystemExit: If mandatory columns are still missing after remapping.

    Example:
        df = load_cve_csv(
            Path("data/raw/cisa_kev.csv"),
            ["cve_id", "published_date"]
        )
    """
    filepath = Path(filepath)
    logging.info(f"Loading CVE dataset: {filepath.name}")

    if not filepath.exists():
        raise FileNotFoundError(
            f"CVE file not found: {filepath}\n"
            f"Run: python -m src.collect_data  to download it."
        )

    try:
        df = pd.read_csv(filepath, encoding="utf-8", low_memory=False)
    except Exception as exc:
        logging.error(f"  [FAIL] Could not read {filepath.name}: {exc}")
        raise

    # Normalise column names first
    df.columns = df.columns.str.strip().str.lower()

    # Auto-detect if this is a KEV file and remap columns
    if "cveid" in df.columns:
        logging.info(f"  Detected CISA KEV format. Remapping columns...")
        df = df.rename(columns=KEV_COLUMN_MAP)
        # Add data_source label (KEV is real public data)
        if "data_source" not in df.columns:
            df["data_source"] = "PUBLIC"
        logging.info(f"  Column remap complete.")

    # Validate mandatory columns
    if not validate_columns(df, mandatory_columns):
        raise SystemExit(
            f"CVE ingestion halted for '{filepath.name}' — required columns missing."
        )

    log_import(filepath, len(df))
    logging.info(
        f"  [OK] Loaded {len(df):,} CVE records from {filepath.name}"
    )
    return df


# =============================================================================
# VALIDATION HELPERS
# =============================================================================

def validate_columns(df: pd.DataFrame, mandatory_columns: list) -> bool:
    """
    Check that all required column names are present in the DataFrame.

    If any mandatory column is missing:
        - Logs a clear error message listing the missing columns.
        - Returns False (the caller should then skip this file).

    If all columns are present:
        - Logs a success message.
        - Returns True.

    Args:
        df (pd.DataFrame): The DataFrame to check.
        mandatory_columns (list): List of column names that must be present.
                                  Column names are compared in lowercase.

    Returns:
        bool: True if all mandatory columns exist, False otherwise.

    Example:
        is_valid = validate_columns(df, ["incident_id", "incident_date", "threat_type"])
    """
    actual_cols  = set(df.columns)
    # Normalise the mandatory list too so comparison is case-insensitive
    required_set = set(c.strip().lower() for c in mandatory_columns)

    missing = required_set - actual_cols

    if missing:
        logging.error(
            f"  [FAIL] Column validation failed. Missing required columns: "
            f"{sorted(missing)}"
        )
        logging.error(
            f"  Columns actually found: {sorted(actual_cols)}"
        )
        return False

    logging.info(
        f"  Column validation passed. All {len(required_set)} required "
        f"columns are present."
    )
    return True


def log_import(filepath: Path, row_count: int, log_dir: Path = None) -> None:
    """
    Append an import record to logs/import_log.txt.

    Each line in the log records:
        - The timestamp of the import
        - The file name
        - How many rows were loaded
        - Status (SUCCESS)

    Args:
        filepath (Path): The file that was imported.
        row_count (int): Number of rows successfully read from the file.
        log_dir (Path): Directory where the import log file lives.
                        Defaults to <project_root>/logs/.

    Example log entry:
        2026-10-25 18:30:00 | FILE: incidents.csv | ROWS: 1500 | STATUS: SUCCESS
    """
    if log_dir is None:
        # Resolve logs/ relative to project root (parent of src/)
        log_dir = Path(__file__).resolve().parent.parent / "logs"

    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    log_path  = log_dir / "import_log.txt"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = (
        f"{timestamp} | FILE: {Path(filepath).name} | "
        f"ROWS: {row_count} | STATUS: SUCCESS\n"
    )

    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(entry)

    logging.info(f"  Import logged to {log_path.name}")


# =============================================================================
# BATCH IMPORT HELPER
# =============================================================================

def load_all_csvs_from_directory(
    directory: Path,
    mandatory_columns: list,
    file_type: str = "incident",
) -> pd.DataFrame:
    """
    Load ALL CSV files found in a given directory and combine them into one DataFrame.

    This is the "batch import" feature (FR-004). It allows you to drop multiple
    CSV files into data/raw/ and import them all at once.

    Files that fail column validation are skipped (logged as warnings).
    Successfully loaded files are stacked vertically (concatenated).

    Args:
        directory (Path): Folder to scan for CSV files.
        mandatory_columns (list): Required column names for each file.
        file_type (str): "incident" (default) or "cve" — determines
                         which loader function is used.

    Returns:
        pd.DataFrame: A single combined DataFrame of all successfully loaded files.
                      Returns an empty DataFrame if no files were loaded.

    Example:
        df = load_all_csvs_from_directory(
            Path("data/raw"),
            ["incident_id", "incident_date", "threat_type"],
        )
    """
    directory = Path(directory)
    logging.info(f"Scanning directory for CSV files: {directory}")

    csv_files = sorted(directory.glob("*.csv"))

    if not csv_files:
        logging.warning(f"  No CSV files found in {directory}")
        return pd.DataFrame()

    logging.info(f"  Found {len(csv_files)} CSV file(s): {[f.name for f in csv_files]}")

    loaded_frames = []
    loader = load_cve_csv if file_type == "cve" else load_incident_csv

    for csv_file in csv_files:
        try:
            df = loader(csv_file, mandatory_columns)
            df["_source_file"] = csv_file.name     # track which file each row came from
            loaded_frames.append(df)
        except (SystemExit, FileNotFoundError, ValueError) as exc:
            logging.warning(f"  [SKIP] {csv_file.name}: {exc}")
        except Exception as exc:
            logging.warning(f"  [SKIP] {csv_file.name} — unexpected error: {exc}")

    if not loaded_frames:
        logging.warning("  No files were loaded successfully.")
        return pd.DataFrame()

    combined = pd.concat(loaded_frames, ignore_index=True)
    logging.info(
        f"  Batch import complete: {len(loaded_frames)} file(s), "
        f"{len(combined):,} total rows."
    )
    return combined

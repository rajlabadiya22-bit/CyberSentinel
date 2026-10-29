"""
main.py — NCTIRAP Pipeline Entry Point
=======================================
National Cyber Threat Intelligence & Risk Analytics Platform

This is the MAIN SCRIPT you run from the command line.
It orchestrates the entire ETL (Extract, Transform, Load) pipeline
by calling the other modules in the correct order.

HOW TO RUN:
    python main.py --input data/raw/incidents.csv

OPTIONAL ARGUMENTS:
    --input  <path>     Path to the incident CSV file (required)
    --cve    <path>     Path to the CVE dataset CSV file (optional)
    --db     <path>     Path to the SQLite database file (default: nctirap.db)

WHAT THIS SCRIPT DOES (in order):
    Step 1 → Load configuration from config/taxonomy.json
    Step 2 → Read and validate the input CSV file
    Step 3 → Clean and standardise the data
    Step 4 → Store cleaned data in the SQLite database
    Step 5 → Compute historical analytics (trends, distributions)
    Step 6 → Compute risk scores (ACRS per sector, NCRI)
    Step 7 → Export all results to output/analytics/ as CSV files
    Step 8 → Generate data quality report to output/reports/

ACADEMIC DISCLAIMER:
    This script is part of an academic prototype. All risk scores produced
    are labelled "Academic Model — Not an Official Government Metric."
    The system does not connect to any network or government database.
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from datetime import datetime

# ─── Set up the project root path so imports work correctly ──────────────────
# This makes sure Python can find the 'src' folder regardless of where you
# run the script from.
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

# ─── Import our custom modules from the src/ folder ──────────────────────────
# NOTE FOR BEGINNERS: Each import below brings in a Python file from src/.
# These will be implemented in later stages. Right now they contain skeletons.
from src.ingestion    import load_incident_csv, validate_columns
from src.cleaning     import clean_incident_data
from src.database     import get_connection, initialise_database, insert_incidents
from src.analytics    import compute_incident_trends, compute_threat_distribution
from src.risk_scoring import compute_sector_risk_scores, compute_national_risk_index
from src.export       import export_analytics_to_csv, generate_quality_report


# =============================================================================
# LOGGING SETUP
# Creates a log file at logs/run_log.txt AND prints to the terminal.
# =============================================================================
def setup_logging(log_dir: Path) -> None:
    """Configure logging to write to both a file and the terminal screen."""
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "run_log.txt"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),   # Write to file
            logging.StreamHandler(sys.stdout),                  # Print to screen
        ],
    )


# =============================================================================
# CONFIGURATION LOADER
# Reads taxonomy.json — the file that defines allowed threat types, sectors, etc.
# =============================================================================
def load_taxonomy(config_path: Path) -> dict:
    """
    Load the taxonomy configuration from config/taxonomy.json.

    Returns a dictionary containing:
        - threat_types: list of allowed threat type strings
        - target_sectors: list of allowed sector strings
        - severity_levels: dict of severity name → numeric weight
        - sector_criticality_weights: dict of sector → SCW value
        - acrs_formula_weights: dict with alpha, beta, gamma
        - mandatory_incident_columns: list of required CSV column names
    """
    if not config_path.exists():
        logging.error(f"Configuration file not found: {config_path}")
        logging.error("Cannot proceed without taxonomy.json. Exiting.")
        sys.exit(1)

    with open(config_path, "r", encoding="utf-8") as f:
        taxonomy = json.load(f)

    logging.info(f"Taxonomy loaded from: {config_path}")
    return taxonomy


# =============================================================================
# ARGUMENT PARSER
# Defines what command-line arguments the user can pass.
# =============================================================================
def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments passed to main.py.

    Example usage:
        python main.py --input data/raw/incidents.csv
        python main.py --input data/synthetic/synthetic_incidents.csv --cve data/raw/cve_data.csv
    """
    parser = argparse.ArgumentParser(
        description=(
            "NCTIRAP — National Cyber Threat Intelligence & Risk Analytics Platform\n"
            "Academic Project — B.Tech Computer Science\n"
            "Disclaimer: All outputs are academic models, not official government metrics."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Path to the incident data CSV file (e.g., data/raw/incidents.csv)",
    )
    parser.add_argument(
        "--cve",
        type=Path,
        required=False,
        default=None,
        help="(Optional) Path to the CVE dataset CSV file",
    )
    parser.add_argument(
        "--db",
        type=Path,
        required=False,
        default=PROJECT_ROOT / "database" / "nctirap.db",
        help="Path to the SQLite database file (default: database/nctirap.db)",
    )

    return parser.parse_args()


# =============================================================================
# MAIN PIPELINE FUNCTION
# This function calls each module in the correct order.
# =============================================================================
def run_pipeline(args: argparse.Namespace, taxonomy: dict) -> None:
    """
    Execute the full NCTIRAP data pipeline.

    Pipeline Steps:
        1. Validate input file exists
        2. Load and validate CSV columns
        3. Clean the data
        4. Initialise and populate the database
        5. Compute analytics (trends, distributions)
        6. Compute risk scores (ACRS, NCRI)
        7. Export results to CSV files
        8. Generate quality report
    """
    pipeline_start = datetime.now()
    logging.info("=" * 60)
    logging.info("NCTIRAP PIPELINE STARTED")
    logging.info(f"Input file : {args.input}")
    logging.info(f"Database   : {args.db}")
    logging.info(f"Start time : {pipeline_start.strftime('%Y-%m-%d %H:%M:%S')}")
    logging.info("=" * 60)

    # ── STEP 1: Validate input file ──────────────────────────────────────────
    logging.info("[Step 1/8] Validating input file...")
    if not args.input.exists():
        logging.error(f"Input file not found: {args.input}")
        logging.error("Please place your CSV file in the data/raw/ folder.")
        sys.exit(1)
    logging.info(f"[Step 1/8] Input file found: {args.input}")

    # ── STEP 2: Load and validate CSV ────────────────────────────────────────
    logging.info("[Step 2/8] Loading and validating CSV columns...")
    raw_df = load_incident_csv(
        filepath=args.input,
        mandatory_columns=taxonomy["mandatory_incident_columns"],
    )
    logging.info(f"[Step 2/8] Loaded {len(raw_df)} raw records from {args.input.name}")

    # ── STEP 3: Clean the data ───────────────────────────────────────────────
    logging.info("[Step 3/8] Cleaning and standardising data...")
    cleaned_df, cleaning_report = clean_incident_data(raw_df, taxonomy)
    logging.info(f"[Step 3/8] Cleaning complete. {len(cleaned_df)} records remain "
                 f"(removed {cleaning_report['duplicates_removed']} duplicates, "
                 f"{cleaning_report['bad_dates_excluded']} bad-date records).")

    # ── STEP 4: Database setup and data storage ───────────────────────────────
    logging.info("[Step 4/8] Connecting to database and storing cleaned data...")
    conn = get_connection(args.db)
    initialise_database(conn, schema_path=PROJECT_ROOT / "database" / "schema.sql")
    records_inserted = insert_incidents(conn, cleaned_df, taxonomy)
    logging.info(f"[Step 4/8] {records_inserted} records inserted into database.")

    # ── STEP 5: Historical analytics ─────────────────────────────────────────
    logging.info("[Step 5/8] Computing historical analytics...")
    trend_results       = compute_incident_trends(conn)
    distribution_results = compute_threat_distribution(conn)
    logging.info("[Step 5/8] Historical analytics complete.")

    # ── STEP 6: Risk scoring ──────────────────────────────────────────────────
    logging.info("[Step 6/8] Computing sector risk scores (ACRS) and national index (NCRI)...")
    sector_scores = compute_sector_risk_scores(conn, taxonomy)
    ncri_result   = compute_national_risk_index(sector_scores, taxonomy)
    logging.info(f"[Step 6/8] Risk scoring complete. NCRI = {ncri_result['ncri_score']:.2f}")
    logging.info("          [Academic Model — Not an Official Government Metric]")

    # ── STEP 7: Export to CSV ─────────────────────────────────────────────────
    logging.info("[Step 7/8] Exporting results to output/analytics/...")
    output_dir = PROJECT_ROOT / "output" / "analytics"
    export_analytics_to_csv(
        output_dir=output_dir,
        trend_results=trend_results,
        distribution_results=distribution_results,
        sector_scores=sector_scores,
        ncri_result=ncri_result,
    )
    logging.info(f"[Step 7/8] CSV files written to: {output_dir}")

    # ── STEP 8: Data quality report ───────────────────────────────────────────
    logging.info("[Step 8/8] Generating data quality report...")
    reports_dir = PROJECT_ROOT / "output" / "reports"
    generate_quality_report(
        reports_dir=reports_dir,
        cleaning_report=cleaning_report,
        raw_row_count=len(raw_df),
        clean_row_count=len(cleaned_df),
    )
    logging.info(f"[Step 8/8] Quality report written to: {reports_dir}")

    # ── DONE ──────────────────────────────────────────────────────────────────
    duration = (datetime.now() - pipeline_start).total_seconds()
    logging.info("=" * 60)
    logging.info("PIPELINE COMPLETED SUCCESSFULLY")
    logging.info(f"Total time : {duration:.1f} seconds")
    logging.info("Next step  : Open Power BI Desktop and connect to output/analytics/")
    logging.info("=" * 60)

    conn.close()


# =============================================================================
# SCRIPT ENTRY POINT
# Python runs this block when you execute: python main.py ...
# =============================================================================
if __name__ == "__main__":
    # Set up paths
    log_dir     = PROJECT_ROOT / "logs"
    config_path = PROJECT_ROOT / "config" / "taxonomy.json"

    # Set up logging first so all messages go to the log file
    setup_logging(log_dir)

    # Parse command-line arguments (e.g., --input data/raw/incidents.csv)
    args = parse_arguments()

    # Load the taxonomy configuration
    taxonomy = load_taxonomy(config_path)

    # Run the pipeline
    run_pipeline(args, taxonomy)

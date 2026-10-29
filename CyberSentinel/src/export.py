"""
src/export.py — CSV Export and Report Generation Module
=========================================================
National Cyber Threat Intelligence & Risk Analytics Platform

PURPOSE:
    This module takes the results produced by analytics.py and risk_scoring.py
    and WRITES THEM TO CSV FILES in the output/analytics/ folder.

    Power BI will read these CSV files to build the dashboards.
    This module is the "last step" in the pipeline.

WHAT THIS MODULE DOES:
    1. Write each analytics result to a separate CSV file.
    2. Generate a data quality report (preprocessing_summary.csv).
    3. Use UTF-8 encoding for all CSV files (so Power BI reads them correctly).
    4. Ensure partial files do not overwrite good files on failure.

OUTPUT FILES CREATED:
    output/analytics/sector_risk_scores.csv    ← ACRS scores per sector
    output/analytics/national_risk_index.csv   ← NCRI score and trend
    output/analytics/incident_trends.csv       ← Monthly incident counts
    output/analytics/threat_distribution.csv   ← Threat type breakdown
    output/analytics/geographic_distribution.csv ← State-level counts
    output/reports/preprocessing_summary.csv   ← Cleaning summary

SRS REFERENCES:
    FR-020 (export analytics to CSV), FR-046 (UTF-8 encoded CSVs),
    FR-047 (execution log), FR-048 (data quality report),
    NFR-005 (partial files must not overwrite good files)
"""

import logging
from pathlib import Path
from datetime import datetime

import pandas as pd


# =============================================================================
# MAIN EXPORT FUNCTION
# =============================================================================

def export_analytics_to_csv(
    output_dir: Path,
    trend_results: pd.DataFrame,
    distribution_results: pd.DataFrame,
    sector_scores: list,
    ncri_result: dict,
) -> None:
    """
    Export all analytics DataFrames to CSV files in the output/analytics/ folder.

    This is the main function called by main.py after all analytics are computed.

    Args:
        output_dir (Path): The output/analytics/ directory path.
        trend_results (pd.DataFrame): Output of compute_incident_trends().
        distribution_results (pd.DataFrame): Output of compute_threat_distribution().
        sector_scores (list): Output of compute_sector_risk_scores() (list of dicts).
        ncri_result (dict): Output of compute_national_risk_index().
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Write incident trends
    if trend_results is not None and not trend_results.empty:
        safe_write_csv(trend_results, output_dir / "incident_trends.csv")

    # Write threat distribution
    if distribution_results is not None and not distribution_results.empty:
        safe_write_csv(distribution_results, output_dir / "threat_distribution.csv")

    # Convert sector_scores list to DataFrame and write
    if sector_scores:
        scores_df = pd.DataFrame(sector_scores)
        safe_write_csv(scores_df, output_dir / "sector_risk_scores.csv")

    # Write NCRI result as a single-row DataFrame
    if ncri_result:
        ncri_df = pd.DataFrame([ncri_result])
        safe_write_csv(ncri_df, output_dir / "national_risk_index.csv")

    logging.info(f"All core analytics and risk CSVs exported to {output_dir}")


def safe_write_csv(df: pd.DataFrame, filepath: Path) -> Path:
    """
    Write a DataFrame to a CSV file SAFELY using atomic write.

    "Safely" means:
        1. Ensure destination directory exists.
        2. Write to a temporary file first (.tmp extension).
        3. Only after the write succeeds, replace/rename the temp file to the final destination.
        4. This prevents a failed write or script termination from corrupting existing data.

    Args:
        df (pd.DataFrame): The DataFrame to write.
        filepath (Path): The final destination file path.

    Returns:
        Path: The path to the successfully written CSV file.
    """
    filepath = Path(filepath)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = filepath.with_suffix(".tmp")

    try:
        df.to_csv(tmp_path, index=False, encoding="utf-8")
        # On Windows, replace() replaces the target file atomically if it exists
        tmp_path.replace(filepath)
        logging.info(f"Safely exported: {filepath.name} ({len(df):,} rows)")
        return filepath
    except Exception as exc:
        logging.error(f"Failed to safely write CSV to {filepath}: {exc}")
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise exc


# =============================================================================
# REPORTING FUNCTIONS
# =============================================================================

def generate_quality_report(
    reports_dir: Path,
    cleaning_report: dict,
    raw_row_count: int,
    clean_row_count: int,
) -> None:
    """
    Generate a data quality summary report and save it to output/reports/.

    This report is saved as preprocessing_summary.csv and summarises:
        - How many rows were in the raw file
        - How many rows were removed (duplicates, bad dates, etc.)
        - How many rows made it into the database
        - Data completeness percentage

    Args:
        reports_dir (Path): The output/reports/ directory path.
        cleaning_report (dict): The report dict from cleaning.py.
        raw_row_count (int): Total rows in the raw input file.
        clean_row_count (int): Total rows after cleaning.
    """
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    completeness_pct = (clean_row_count / raw_row_count * 100) if raw_row_count > 0 else 0
    summary = {
        **cleaning_report,
        "raw_row_count": raw_row_count,
        "clean_row_count": clean_row_count,
        "data_completeness_pct": round(completeness_pct, 2),
        "report_generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    summary_df = pd.DataFrame([summary])
    safe_write_csv(summary_df, reports_dir / "preprocessing_summary.csv")
    logging.info(f"Quality report saved to {reports_dir / 'preprocessing_summary.csv'}")

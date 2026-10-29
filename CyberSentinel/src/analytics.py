"""
src/analytics.py — Historical Cybersecurity Analytics Module
==============================================================
National Cyber Threat Intelligence & Risk Analytics Platform

PURPOSE:
    This module performs historical threat intelligence and vulnerability
    analytics using Python, Pandas, and NumPy.

    It computes descriptive statistics, temporal trends, categorical breakdowns,
    and sector comparisons across historical cyber incidents and disclosed
    vulnerability datasets.

KEY ANALYSES IMPLEMENTED:
    1. Incident counts by attack/threat type (with percentage and rankings).
    2. Incident counts by severity (Critical, High, Medium, Low, Unknown).
    3. Temporal incident trends by year and month (monthly and annual YoY change).
    4. Sector-level comparative analysis (incident volume, severity profile, top threats).
    5. Identification of top N most frequent attack types (defaults to top 5).
    6. Vulnerability severity and CVSS score summary (NVD CVE and CISA KEV feeds).
    7. Overall descriptive statistics with clear provenance labeling and date ranges.
    8. Safe CSV export to output/analytics/ and data/processed/.

METHODOLOGICAL RULES ENFORCED:
    - Incident statistics are kept strictly separate from vulnerability counts.
    - Synthetic datasets are explicitly labeled (`data_source = 'SYNTHETIC'`).
    - Real datasets are explicitly labeled (`data_source = 'PUBLIC'`).
    - If a field is missing, the analysis is safely skipped with an explanation.
    - Statistical associations reflect observed sample frequency and DO NOT prove causation.

SRS REFERENCES:
    FR-014 (incident frequency by year/month), FR-015 (threat type distribution),
    FR-016 (top 5 threat types), FR-017 (YoY change), FR-018 (top sector by year),
    FR-019 (financial loss if available), FR-020 (export to CSV),
    FR-037 to FR-042 (vulnerability intelligence).
"""

import argparse
import logging
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple, Union

import numpy as np
import pandas as pd

# Project directory resolution
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "database" / "nctirap.db"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "output" / "analytics"
PROCESSED_DATA_DIR = PROJECT_ROOT / "data" / "processed"

# Import safe_write_csv from export.py
sys.path.insert(0, str(PROJECT_ROOT))
try:
    from src.export import safe_write_csv
except ImportError:
    def safe_write_csv(df: pd.DataFrame, filepath: Path) -> Path:
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        tmp = filepath.with_suffix(".tmp")
        df.to_csv(tmp, index=False, encoding="utf-8")
        tmp.replace(filepath)
        return filepath


# =============================================================================
# DATA RESOLUTION HELPERS (Supports DataFrame, SQLite Connection, or CSV Path)
# =============================================================================

def _resolve_incident_dataframe(
    source: Optional[Union[pd.DataFrame, sqlite3.Connection, Path, str]] = None
) -> Tuple[pd.DataFrame, str]:
    """
    Resolve and return a standardized incident DataFrame along with its provenance label.

    Accepts:
        - pd.DataFrame: returns a copy with standardized column names.
        - sqlite3.Connection: queries INCIDENTS joined with lookup tables.
        - Path/str: loads CSV from file path.
        - None: attempts to load from default SQLite DB, or fallback processed CSV.

    Returns:
        Tuple[pd.DataFrame, str]: (DataFrame, provenance_label)
    """
    label = "UNKNOWN"

    if isinstance(source, pd.DataFrame):
        df = source.copy()
        if "data_source" in df.columns and not df["data_source"].empty:
            label = str(df["data_source"].iloc[0])
        return df, label

    if isinstance(source, sqlite3.Connection):
        query = """
            SELECT 
                i.incident_id,
                i.incident_date,
                t.threat_type_name AS threat_type,
                s.sector_name AS target_sector,
                sev.severity_name AS severity,
                i.target_state,
                i.financial_loss_inr,
                i.resolution_days,
                i.description,
                i.data_source
            FROM INCIDENTS i
            LEFT JOIN THREAT_TYPES t ON i.threat_type_fk = t.threat_type_id
            LEFT JOIN SECTORS s ON i.sector_fk = s.sector_id
            LEFT JOIN SEVERITY_LEVELS sev ON i.severity_fk = sev.severity_id
        """
        df = pd.read_sql_query(query, source)
        if not df.empty and "data_source" in df.columns:
            label = str(df["data_source"].iloc[0])
        return df, label

    # Path or string given
    if source is not None:
        p = Path(source)
        if p.exists():
            if p.suffix.lower() == ".db":
                try:
                    conn = sqlite3.connect(str(p))
                    df, label = _resolve_incident_dataframe(conn)
                    conn.close()
                    return df, label
                except Exception as exc:
                    logging.warning(f"Failed to query SQLite database at {p}: {exc}")
            try:
                df = pd.read_csv(p, encoding="utf-8")
                if "data_source" in df.columns and not df["data_source"].empty:
                    label = str(df["data_source"].iloc[0])
                return df, label
            except Exception as exc:
                logging.warning(f"Failed to read CSV at {p}: {exc}")

    # Default fallback: check SQLite database first
    if DEFAULT_DB_PATH.exists():
        try:
            conn = sqlite3.connect(str(DEFAULT_DB_PATH))
            df, label = _resolve_incident_dataframe(conn)
            conn.close()
            if not df.empty:
                return df, label
        except Exception as e:
            logging.warning(f"Could not load from default database: {e}")

    # Fallback to processed CSV
    fallback_csv = PROCESSED_DATA_DIR / "incidents_cleaned.csv"
    if fallback_csv.exists():
        df = pd.read_csv(fallback_csv, encoding="utf-8")
        if "data_source" in df.columns and not df["data_source"].empty:
            label = str(df["data_source"].iloc[0])
        return df, label

    logging.warning("No incident data source could be resolved. Returning empty DataFrame.")
    return pd.DataFrame(), label


def _resolve_cve_dataframe(
    source: Optional[Union[pd.DataFrame, sqlite3.Connection, Path, str]] = None
) -> Tuple[pd.DataFrame, str]:
    """
    Resolve and return a standardized CVE vulnerability DataFrame.
    """
    label = "PUBLIC"

    if isinstance(source, pd.DataFrame):
        df = source.copy()
        if "data_source" in df.columns and not df["data_source"].empty:
            label = str(df["data_source"].iloc[0])
        return df, label

    if isinstance(source, sqlite3.Connection):
        query = """
            SELECT 
                cve_id,
                published_date,
                cvss_base_score,
                cvss_severity,
                vendor,
                product,
                description
            FROM CVE_RECORDS
        """
        df = pd.read_sql_query(query, source)
        df["data_source"] = "PUBLIC"
        return df, "PUBLIC"

    if source is not None:
        p = Path(source)
        if p.exists():
            if p.suffix.lower() == ".db":
                try:
                    conn = sqlite3.connect(str(p))
                    df, label = _resolve_cve_dataframe(conn)
                    conn.close()
                    return df, label
                except Exception as exc:
                    logging.warning(f"Failed to query SQLite database at {p}: {exc}")
            try:
                df = pd.read_csv(p, encoding="utf-8")
                return df, label
            except Exception as exc:
                logging.warning(f"Failed to read CSV at {p}: {exc}")

    # Check default DB
    if DEFAULT_DB_PATH.exists():
        try:
            conn = sqlite3.connect(str(DEFAULT_DB_PATH))
            df, label = _resolve_cve_dataframe(conn)
            conn.close()
            if not df.empty:
                return df, label
        except Exception as e:
            logging.warning(f"Could not load CVE records from database: {e}")

    # Fallback to processed NVD CSV
    fallback_csv = PROCESSED_DATA_DIR / "nvd_cleaned.csv"
    if fallback_csv.exists():
        return pd.read_csv(fallback_csv, encoding="utf-8"), "PUBLIC"

    return pd.DataFrame(), label


def _resolve_kev_dataframe(
    source: Optional[Union[pd.DataFrame, Path, str]] = None
) -> Tuple[pd.DataFrame, str]:
    """Resolve and return CISA KEV catalog DataFrame."""
    if isinstance(source, pd.DataFrame):
        return source.copy(), "PUBLIC"

    if source is not None:
        p = Path(source)
        if p.exists():
            return pd.read_csv(p, encoding="utf-8"), "PUBLIC"

    # Default fallback paths
    for p in [PROCESSED_DATA_DIR / "kev_cleaned.csv", PROJECT_ROOT / "data" / "raw" / "cisa_kev.csv"]:
        if p.exists():
            return pd.read_csv(p, encoding="utf-8"), "PUBLIC"

    return pd.DataFrame(), "PUBLIC"


# =============================================================================
# 1. INCIDENT COUNTS BY ATTACK TYPE (SRS FR-015, FR-016)
# =============================================================================

def count_incidents_by_attack_type(
    data: Optional[Union[pd.DataFrame, sqlite3.Connection, Path, str]] = None
) -> pd.DataFrame:
    """
    Count cyber incidents grouped by attack / threat type.

    Calculates:
        - Incident count per threat type.
        - Percentage share of total incidents (rounded to 2 decimal places).
        - Rank from 1 (most frequent) to N.
        - Cumulative percentage of incidents.

    Args:
        data: Incident DataFrame, SQLite Connection, or CSV Path.

    Returns:
        pd.DataFrame: Columns ['rank', 'threat_type', 'incident_count', 'percentage', 'cumulative_percentage']
    """
    df, provenance = _resolve_incident_dataframe(data)

    col = None
    for candidate in ["threat_type", "attack_type", "threat_type_name"]:
        if candidate in df.columns:
            col = candidate
            break

    if col is None or df.empty:
        logging.warning("Analysis 1 Skipped: 'threat_type' column not found or dataset is empty.")
        return pd.DataFrame(columns=["rank", "threat_type", "incident_count", "percentage", "cumulative_percentage"])

    # Group and aggregate
    counts = df[col].dropna().value_counts().reset_index()
    counts.columns = ["threat_type", "incident_count"]

    total = counts["incident_count"].sum()
    if total > 0:
        counts["percentage"] = (counts["incident_count"] / total * 100).round(2)
        counts["cumulative_percentage"] = counts["percentage"].cumsum().round(2)
    else:
        counts["percentage"] = 0.0
        counts["cumulative_percentage"] = 0.0

    counts["rank"] = range(1, len(counts) + 1)
    counts["data_source"] = provenance

    # Reorder columns
    result = counts[["rank", "threat_type", "incident_count", "percentage", "cumulative_percentage", "data_source"]]
    logging.info(f"Computed attack type distribution ({len(result)} distinct threat types).")
    return result


# Compatibility alias for main.py
compute_threat_distribution = count_incidents_by_attack_type


# =============================================================================
# 2. INCIDENT COUNTS BY SEVERITY (SRS FR-023)
# =============================================================================

def count_incidents_by_severity(
    data: Optional[Union[pd.DataFrame, sqlite3.Connection, Path, str]] = None
) -> pd.DataFrame:
    """
    Count cyber incidents grouped by assigned severity level.

    Orders severity in standard analytical hierarchy:
    Critical -> High -> Medium -> Low -> Unknown.

    Args:
        data: Incident DataFrame, SQLite Connection, or CSV Path.

    Returns:
        pd.DataFrame: Columns ['severity', 'incident_count', 'percentage', 'data_source']
    """
    df, provenance = _resolve_incident_dataframe(data)

    col = None
    for candidate in ["severity", "severity_name", "severity_level"]:
        if candidate in df.columns:
            col = candidate
            break

    if col is None or df.empty:
        logging.warning("Analysis 2 Skipped: 'severity' column not found or dataset is empty.")
        return pd.DataFrame(columns=["severity", "incident_count", "percentage", "data_source"])

    counts = df[col].astype(str).str.strip().str.capitalize().value_counts().reset_index()
    counts.columns = ["severity", "incident_count"]

    total = counts["incident_count"].sum()
    counts["percentage"] = (counts["incident_count"] / total * 100).round(2) if total > 0 else 0.0
    counts["data_source"] = provenance

    # Sort logically
    hierarchy = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Unknown": 5}
    counts["sort_order"] = counts["severity"].map(lambda s: hierarchy.get(s, 99))
    counts = counts.sort_values("sort_order").drop(columns=["sort_order"]).reset_index(drop=True)

    logging.info(f"Computed severity distribution ({len(counts)} severity categories).")
    return counts


# =============================================================================
# 3. TEMPORAL INCIDENT TRENDS (SRS FR-014, FR-017)
# =============================================================================

def analyze_incident_trends(
    data: Optional[Union[pd.DataFrame, sqlite3.Connection, Path, str]] = None
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Analyze cyber incident temporal trends at monthly and annual levels.

    Computes:
        - Monthly trend: frequency of incidents per calendar month.
        - Annual trend: frequency of incidents per calendar year, including
          Year-over-Year (YoY) absolute change and YoY percentage change.

    Args:
        data: Incident DataFrame, SQLite Connection, or CSV Path.

    Returns:
        Tuple[pd.DataFrame, pd.DataFrame]: (monthly_trends_df, annual_trends_df)
    """
    df, provenance = _resolve_incident_dataframe(data)

    if "incident_date" not in df.columns or df.empty:
        logging.warning("Analysis 3 Skipped: 'incident_date' column not found or dataset is empty.")
        empty_monthly = pd.DataFrame(columns=["year", "month", "month_label", "incident_count", "data_source"])
        empty_annual = pd.DataFrame(columns=["year", "incident_count", "count_previous_year", "yoy_change_absolute", "yoy_change_pct", "data_source"])
        return empty_monthly, empty_annual

    # Parse dates cleanly (standard ISO YYYY-MM-DD or mixed formats)
    dates = pd.to_datetime(df["incident_date"], format="mixed", errors="coerce")
    valid_mask = dates.notna()

    if valid_mask.sum() == 0:
        logging.warning("Analysis 3 Skipped: No parseable dates found in 'incident_date'.")
        return pd.DataFrame(), pd.DataFrame()

    temp = df[valid_mask].copy()
    temp["_dt"] = dates[valid_mask]
    temp["year"] = temp["_dt"].dt.year
    temp["month"] = temp["_dt"].dt.month
    temp["month_label"] = temp["_dt"].dt.strftime("%Y-%m")

    # Monthly trends
    monthly = temp.groupby(["year", "month", "month_label"]).size().reset_index(name="incident_count")
    monthly = monthly.sort_values(["year", "month"]).reset_index(drop=True)
    monthly["data_source"] = provenance

    # Annual trends & YoY change
    annual = temp.groupby("year").size().reset_index(name="incident_count")
    annual = annual.sort_values("year").reset_index(drop=True)

    annual["count_previous_year"] = annual["incident_count"].shift(1)
    annual["yoy_change_absolute"] = annual["incident_count"] - annual["count_previous_year"]

    # YoY Percentage = ((count_this_year - count_last_year) / count_last_year) * 100
    annual["yoy_change_pct"] = np.where(
        annual["count_previous_year"].notna() & (annual["count_previous_year"] > 0),
        ((annual["yoy_change_absolute"] / annual["count_previous_year"]) * 100).round(2),
        np.nan
    )
    annual["data_source"] = provenance

    logging.info(f"Computed temporal trends ({len(annual)} years, {len(monthly)} months).")
    return monthly, annual


# Compatibility alias for main.py (returns monthly trend DataFrame)
def compute_incident_trends(data: Optional[Union[pd.DataFrame, sqlite3.Connection, Path, str]] = None) -> pd.DataFrame:
    monthly, _ = analyze_incident_trends(data)
    return monthly


def compute_year_over_year_change(
    data: Optional[Union[pd.DataFrame, sqlite3.Connection, Path, str]] = None
) -> pd.DataFrame:
    """
    Compute Year-over-Year (YoY) percentage change broken down by threat type (FR-017).

    Args:
        data: Incident DataFrame, SQLite Connection, or CSV Path.

    Returns:
        pd.DataFrame: Columns ['threat_type', 'year', 'count_this_year', 'count_last_year', 'yoy_change_pct', 'data_source']
    """
    df, provenance = _resolve_incident_dataframe(data)

    if "incident_date" not in df.columns or "threat_type" not in df.columns or df.empty:
        logging.warning("YoY by threat type skipped: mandatory columns missing.")
        return pd.DataFrame(columns=["threat_type", "year", "count_this_year", "count_last_year", "yoy_change_pct", "data_source"])

    dates = pd.to_datetime(df["incident_date"], format="mixed", errors="coerce")
    valid_mask = dates.notna()

    temp = df[valid_mask].copy()
    temp["year"] = dates[valid_mask].dt.year

    grouped = temp.groupby(["threat_type", "year"]).size().reset_index(name="incident_count")
    grouped = grouped.sort_values(["threat_type", "year"]).reset_index(drop=True)

    rows = []
    for threat, group in grouped.groupby("threat_type"):
        group = group.sort_values("year").copy()
        group["count_last_year"] = group["incident_count"].shift(1)
        group["yoy_change_pct"] = np.where(
            group["count_last_year"].notna() & (group["count_last_year"] > 0),
            (((group["incident_count"] - group["count_last_year"]) / group["count_last_year"]) * 100).round(2),
            np.nan
        )
        for _, r in group.iterrows():
            if pd.notna(r["count_last_year"]):
                rows.append({
                    "threat_type": threat,
                    "year": int(r["year"]),
                    "count_this_year": int(r["incident_count"]),
                    "count_last_year": int(r["count_last_year"]),
                    "yoy_change_pct": r["yoy_change_pct"],
                    "data_source": provenance
                })

    result = pd.DataFrame(rows)
    logging.info(f"Computed threat type YoY change ({len(result)} records).")
    return result


# =============================================================================
# 4. SECTOR COMPARISON ANALYSIS (SRS FR-018, FR-021)
# =============================================================================

def compare_sectors(
    data: Optional[Union[pd.DataFrame, sqlite3.Connection, Path, str]] = None
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Perform comparative analysis across critical infrastructure sectors.

    Produces:
        1. Sector overview: Total incidents, percentage share, rank, and primary threat.
        2. Sector-Severity cross-tabulation: Critical, High, Medium, Low count per sector.
        3. Most targeted sector by calendar year (FR-018).

    Note on non-causation:
        Observed variations reflect reporting volume in the sample dataset.
        Higher incident counts do NOT prove or imply that a sector is inherently
        less secure without normalizing by digital footprint and asset density.

    Args:
        data: Incident DataFrame, SQLite Connection, or CSV Path.

    Returns:
        Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]: (sector_summary, sector_severity_crosstab, top_sector_by_year)
    """
    df, provenance = _resolve_incident_dataframe(data)

    col = None
    for candidate in ["target_sector", "sector_name", "sector"]:
        if candidate in df.columns:
            col = candidate
            break

    if col is None or df.empty:
        logging.warning("Analysis 4 Skipped: 'target_sector' column not found or dataset is empty.")
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()

    # 1. Sector summary
    sector_counts = df[col].value_counts().reset_index()
    sector_counts.columns = ["sector_name", "incident_count"]
    total = sector_counts["incident_count"].sum()
    sector_counts["percentage"] = (sector_counts["incident_count"] / total * 100).round(2) if total > 0 else 0.0
    sector_counts["rank"] = range(1, len(sector_counts) + 1)
    sector_counts["data_source"] = provenance

    # Primary threat per sector
    if "threat_type" in df.columns:
        primary_threats = df.groupby([col, "threat_type"]).size().reset_index(name="cnt")
        idx = primary_threats.groupby(col)["cnt"].idxmax()
        top_threat_per_sector = primary_threats.loc[idx, [col, "threat_type", "cnt"]]
        top_threat_per_sector.columns = ["sector_name", "top_threat_type", "top_threat_count"]
        sector_counts = sector_counts.merge(top_threat_per_sector, on="sector_name", how="left")

    # Optional fields validation: financial loss / resolution days
    if "financial_loss_inr" in df.columns:
        valid_losses = pd.to_numeric(df["financial_loss_inr"], errors="coerce")
        valid_losses = valid_losses[(valid_losses.notna()) & (valid_losses > 0)]
        if not valid_losses.empty:
            loss_summary = df.groupby(col)["financial_loss_inr"].agg(["mean", "median"]).round(2).reset_index()
            loss_summary.columns = ["sector_name", "avg_loss_inr", "median_loss_inr"]
            sector_counts = sector_counts.merge(loss_summary, on="sector_name", how="left")
        else:
            logging.info("Optional field 'financial_loss_inr' contains only sentinels or nulls. Skipping loss aggregation.")

    # 2. Sector-Severity cross-tabulation
    if "severity" in df.columns:
        crosstab = pd.crosstab(df[col], df["severity"], margins=True, margins_name="Total").reset_index()
        crosstab = crosstab.rename(columns={col: "sector_name"})
        crosstab["data_source"] = provenance
    else:
        crosstab = pd.DataFrame()

    # 3. Top sector by calendar year (FR-018)
    top_sector_by_year_df = pd.DataFrame()
    if "incident_date" in df.columns:
        dates = pd.to_datetime(df["incident_date"], format="mixed", errors="coerce")
        valid_mask = dates.notna()
        if valid_mask.sum() > 0:
            temp = df[valid_mask].copy()
            temp["year"] = dates[valid_mask].dt.year
            year_sector = temp.groupby(["year", col]).size().reset_index(name="incident_count")
            year_totals = temp.groupby("year").size().reset_index(name="total_year_incidents")

            # Find maximum per year
            idx_max = year_sector.groupby("year")["incident_count"].idxmax()
            top_sector_by_year_df = year_sector.loc[idx_max].merge(year_totals, on="year")
            top_sector_by_year_df["sector_pct_of_year"] = (
                top_sector_by_year_df["incident_count"] / top_sector_by_year_df["total_year_incidents"] * 100
            ).round(2)
            top_sector_by_year_df = top_sector_by_year_df.rename(columns={col: "top_sector"})
            top_sector_by_year_df["data_source"] = provenance

    logging.info(f"Completed sector comparative analysis ({len(sector_counts)} sectors).")
    return sector_counts, crosstab, top_sector_by_year_df


# =============================================================================
# 5. TOP N ATTACK TYPES (SRS FR-016)
# =============================================================================

def identify_top_attack_types(
    data: Optional[Union[pd.DataFrame, sqlite3.Connection, Path, str]] = None,
    top_n: int = 5
) -> pd.DataFrame:
    """
    Identify the top N most frequent attack types in the selected dataset.

    Args:
        data: Incident DataFrame, SQLite Connection, or CSV Path.
        top_n: Number of top attack types to return (defaults to 5 as per SRS FR-016).

    Returns:
        pd.DataFrame: Top N attack types with count, percentage, and cumulative share.
    """
    df_attacks = count_incidents_by_attack_type(data)
    if df_attacks.empty:
        return pd.DataFrame()

    top_df = df_attacks.head(top_n).copy()
    top_total_share = top_df["percentage"].sum().round(2)
    logging.info(f"Top {top_n} attack types account for {top_total_share}% of total incidents.")
    return top_df


# =============================================================================
# 6. VULNERABILITY INTELLIGENCE & CVSS ANALYSIS (SRS FR-037 to FR-042)
# =============================================================================

def summarize_vulnerabilities(
    cve_data: Optional[Union[pd.DataFrame, sqlite3.Connection, Path, str]] = None,
    kev_data: Optional[Union[pd.DataFrame, Path, str]] = None
) -> Dict[str, pd.DataFrame]:
    """
    Summarize vulnerability severity ratings and CVSS scores.

    Rules applied:
        - Kept strictly separate from incident statistics.
        - Analyzes CVSS scores and severities from official NVD/CISA feeds.
        - Computes descriptive statistics for numeric CVSS base scores.
        - Examines CISA KEV exploitation and ransomware use if available.

    Args:
        cve_data: NVD CVE DataFrame, SQLite Connection, or CSV Path.
        kev_data: Optional CISA KEV DataFrame or CSV Path.

    Returns:
        Dict[str, pd.DataFrame]: Dictionary of result DataFrames:
            'severity_summary': Count & percentage per CVSS severity.
            'cvss_statistics': Descriptive stats (mean, median, IQR, std, quartiles).
            'cvss_score_distribution': Binned distribution by standard CVSS score ranges.
            'kev_summary': CISA KEV exploitation and ransomware summary (if KEV provided).
    """
    df_cve, cve_provenance = _resolve_cve_dataframe(cve_data)
    results = {}

    if df_cve.empty:
        logging.warning("Analysis 6 Skipped: No CVE vulnerability data available.")
        return results

    # 1. Severity Distribution
    if "cvss_severity" in df_cve.columns:
        sev_counts = df_cve["cvss_severity"].astype(str).str.strip().str.capitalize().value_counts().reset_index()
        sev_counts.columns = ["cvss_severity", "vulnerability_count"]
        total_vulns = sev_counts["vulnerability_count"].sum()
        sev_counts["percentage"] = (sev_counts["vulnerability_count"] / total_vulns * 100).round(2) if total_vulns > 0 else 0.0

        # Sort order
        h = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Unknown": 5}
        sev_counts["order"] = sev_counts["cvss_severity"].map(lambda s: h.get(s, 99))
        sev_counts = sev_counts.sort_values("order").drop(columns=["order"]).reset_index(drop=True)
        sev_counts["data_source"] = cve_provenance
        results["severity_summary"] = sev_counts

    # 2. CVSS Base Score Statistics (Numeric)
    if "cvss_base_score" in df_cve.columns:
        numeric_scores = pd.to_numeric(df_cve["cvss_base_score"], errors="coerce")
        # Valid non-zero CVSS scores
        valid_scores = numeric_scores[(numeric_scores.notna()) & (numeric_scores > 0.0)]
        unscored_count = len(df_cve) - len(valid_scores)

        if not valid_scores.empty:
            q25 = float(np.percentile(valid_scores, 25))
            q75 = float(np.percentile(valid_scores, 75))
            iqr = round(q75 - q25, 2)

            stats_data = [
                {"metric": "total_cve_records", "value": len(df_cve)},
                {"metric": "scored_cve_count", "value": len(valid_scores)},
                {"metric": "unscored_or_unknown_count", "value": unscored_count},
                {"metric": "mean_cvss_score", "value": round(float(valid_scores.mean()), 2)},
                {"metric": "median_cvss_score", "value": round(float(valid_scores.median()), 2)},
                {"metric": "std_deviation", "value": round(float(valid_scores.std()), 2)},
                {"metric": "min_cvss_score", "value": round(float(valid_scores.min()), 2)},
                {"metric": "max_cvss_score", "value": round(float(valid_scores.max()), 2)},
                {"metric": "25th_percentile_q1", "value": round(q25, 2)},
                {"metric": "75th_percentile_q3", "value": round(q75, 2)},
                {"metric": "interquartile_range_iqr", "value": iqr},
            ]
            stats_df = pd.DataFrame(stats_data)
            stats_df["data_source"] = cve_provenance
            results["cvss_statistics"] = stats_df

            # Score Range Distribution (Standard CVSS v3 ranges)
            bins = [-0.1, 0.0, 3.9, 6.9, 8.9, 10.0]
            labels = ["Unscored / 0.0", "Low (0.1–3.9)", "Medium (4.0–6.9)", "High (7.0–8.9)", "Critical (9.0–10.0)"]
            score_cats = pd.cut(numeric_scores.fillna(0.0), bins=bins, labels=labels)
            dist_df = score_cats.value_counts()[labels].reset_index()
            dist_df.columns = ["cvss_score_range", "vulnerability_count"]
            dist_df["percentage"] = (dist_df["vulnerability_count"] / len(df_cve) * 100).round(2)
            dist_df["data_source"] = cve_provenance
            results["cvss_score_distribution"] = dist_df

    # 3. CISA KEV Summary (if available)
    df_kev, kev_prov = _resolve_kev_dataframe(kev_data)
    if not df_kev.empty:
        kev_summary_rows = [
            {"metric": "total_known_exploited_vulnerabilities", "value": len(df_kev)}
        ]
        if "known_ransomware_use" in df_kev.columns:
            rw_counts = df_kev["known_ransomware_use"].value_counts().to_dict()
            for k, v in rw_counts.items():
                kev_summary_rows.append({"metric": f"ransomware_campaign_use_{str(k).lower()}", "value": v})

        if "published_date" in df_kev.columns or "dateAdded" in df_kev.columns:
            dcol = "published_date" if "published_date" in df_kev.columns else "dateAdded"
            kdates = pd.to_datetime(df_kev[dcol], errors="coerce").dropna()
            if not kdates.empty:
                kev_summary_rows.append({"metric": "earliest_kev_date_added", "value": str(kdates.min().date())})
                kev_summary_rows.append({"metric": "latest_kev_date_added", "value": str(kdates.max().date())})

        kev_df = pd.DataFrame(kev_summary_rows)
        kev_df["data_source"] = kev_prov
        results["kev_summary"] = kev_df

    logging.info(f"Summarized vulnerability intelligence ({len(results)} tables created).")
    return results


# =============================================================================
# 7. DESCRIPTIVE STATISTICS & METADATA SUMMARY
# =============================================================================

def calculate_descriptive_statistics(
    incidents_data: Optional[Union[pd.DataFrame, sqlite3.Connection, Path, str]] = None,
    cve_data: Optional[Union[pd.DataFrame, sqlite3.Connection, Path, str]] = None,
    kev_data: Optional[Union[pd.DataFrame, Path, str]] = None
) -> pd.DataFrame:
    """
    Calculate overarching descriptive statistics and record dataset metadata.

    Enforces:
        - Explicit labeling of datasets (name, source, provenance).
        - Documented time periods (start date to end date).
        - Separation of incident statistics from vulnerability counts.
        - Methodological note: correlation does not prove causation.

    Returns:
        pd.DataFrame: Columns ['category', 'dataset_name', 'data_provenance', 'metric', 'value', 'notes']
    """
    df_inc, inc_prov = _resolve_incident_dataframe(incidents_data)
    df_cve, cve_prov = _resolve_cve_dataframe(cve_data)
    df_kev, _ = _resolve_kev_dataframe(kev_data)

    records = []

    # Incident Dataset Metrics
    if not df_inc.empty:
        inc_dates = pd.to_datetime(df_inc.get("incident_date", pd.Series(dtype="object")), format="mixed", errors="coerce").dropna()
        start_date = str(inc_dates.min().date()) if not inc_dates.empty else "N/A"
        end_date = str(inc_dates.max().date()) if not inc_dates.empty else "N/A"

        records.extend([
            {
                "category": "Incident Intelligence",
                "dataset_name": "India Critical Infrastructure Cyber Incidents",
                "data_provenance": inc_prov,
                "metric": "incident_time_period_start",
                "value": start_date,
                "notes": "Earliest incident timestamp in dataset"
            },
            {
                "category": "Incident Intelligence",
                "dataset_name": "India Critical Infrastructure Cyber Incidents",
                "data_provenance": inc_prov,
                "metric": "incident_time_period_end",
                "value": end_date,
                "notes": "Latest incident timestamp in dataset"
            },
            {
                "category": "Incident Intelligence",
                "dataset_name": "India Critical Infrastructure Cyber Incidents",
                "data_provenance": inc_prov,
                "metric": "total_incidents_analyzed",
                "value": len(df_inc),
                "notes": "Valid deduplicated incident records"
            },
            {
                "category": "Incident Intelligence",
                "dataset_name": "India Critical Infrastructure Cyber Incidents",
                "data_provenance": inc_prov,
                "metric": "distinct_threat_types",
                "value": df_inc["threat_type"].nunique() if "threat_type" in df_inc.columns else 0,
                "notes": "Unique attack types identified"
            },
            {
                "category": "Incident Intelligence",
                "dataset_name": "India Critical Infrastructure Cyber Incidents",
                "data_provenance": inc_prov,
                "metric": "distinct_sectors_monitored",
                "value": df_inc["target_sector"].nunique() if "target_sector" in df_inc.columns else 0,
                "notes": "Critical infrastructure sectors monitored"
            },
        ])

        # Monthly mean and std
        if not inc_dates.empty:
            monthly_counts = df_inc.groupby(inc_dates.dt.to_period("M")).size()
            records.extend([
                {
                    "category": "Incident Intelligence",
                    "dataset_name": "India Critical Infrastructure Cyber Incidents",
                    "data_provenance": inc_prov,
                    "metric": "mean_monthly_incident_volume",
                    "value": round(float(monthly_counts.mean()), 2),
                    "notes": "Average incidents reported per month"
                },
                {
                    "category": "Incident Intelligence",
                    "dataset_name": "India Critical Infrastructure Cyber Incidents",
                    "data_provenance": inc_prov,
                    "metric": "std_monthly_incident_volume",
                    "value": round(float(monthly_counts.std()), 2),
                    "notes": "Standard deviation across monthly incident counts"
                },
            ])

        # Top attack type
        if "threat_type" in df_inc.columns:
            top_t = df_inc["threat_type"].value_counts()
            if not top_t.empty:
                top_name = top_t.index[0]
                top_pct = round(top_t.iloc[0] / len(df_inc) * 100, 2)
                records.append({
                    "category": "Incident Intelligence",
                    "dataset_name": "India Critical Infrastructure Cyber Incidents",
                    "data_provenance": inc_prov,
                    "metric": "predominant_threat_type",
                    "value": f"{top_name} ({top_pct}%)",
                    "notes": "Most frequent cyber threat vector"
                })

    # Vulnerability Intelligence Metrics (NVD)
    if not df_cve.empty:
        cve_dates = pd.to_datetime(df_cve.get("published_date", pd.Series(dtype="object")), format="mixed", errors="coerce").dropna()
        cve_start = str(cve_dates.min().date()) if not cve_dates.empty else "N/A"
        cve_end = str(cve_dates.max().date()) if not cve_dates.empty else "N/A"

        records.extend([
            {
                "category": "Vulnerability Intelligence",
                "dataset_name": "NIST National Vulnerability Database (CVE 2.0)",
                "data_provenance": cve_prov,
                "metric": "cve_time_period_start",
                "value": cve_start,
                "notes": "Earliest CVE publication date"
            },
            {
                "category": "Vulnerability Intelligence",
                "dataset_name": "NIST National Vulnerability Database (CVE 2.0)",
                "data_provenance": cve_prov,
                "metric": "cve_time_period_end",
                "value": cve_end,
                "notes": "Latest CVE publication date"
            },
            {
                "category": "Vulnerability Intelligence",
                "dataset_name": "NIST National Vulnerability Database (CVE 2.0)",
                "data_provenance": cve_prov,
                "metric": "total_vulnerabilities_analyzed",
                "value": len(df_cve),
                "notes": "Total public CVE records"
            },
        ])

        if "cvss_base_score" in df_cve.columns:
            sc = pd.to_numeric(df_cve["cvss_base_score"], errors="coerce")
            valid_sc = sc[(sc.notna()) & (sc > 0.0)]
            if not valid_sc.empty:
                records.append({
                    "category": "Vulnerability Intelligence",
                    "dataset_name": "NIST National Vulnerability Database (CVE 2.0)",
                    "data_provenance": cve_prov,
                    "metric": "mean_cvss_base_score",
                    "value": round(float(valid_sc.mean()), 2),
                    "notes": "Mean base severity score on a 0.0–10.0 scale"
                })

    # CISA KEV Metrics
    if not df_kev.empty:
        records.append({
            "category": "Vulnerability Intelligence",
            "dataset_name": "CISA Known Exploited Vulnerabilities (KEV)",
            "data_provenance": "PUBLIC",
            "metric": "actively_exploited_vulnerabilities",
            "value": len(df_kev),
            "notes": "Vulnerabilities with confirmed active exploitation in the wild"
        })

    # Methodological & Academic Disclaimers
    records.append({
        "category": "Methodological Governance",
        "dataset_name": "All Datasets",
        "data_provenance": "ACADEMIC PROTOCOL",
        "metric": "correlation_causation_policy",
        "value": "Non-Causation Enforced",
        "notes": "Statistical frequency does NOT prove causation. Frequencies reflect sample reporting patterns."
    })
    records.append({
        "category": "Methodological Governance",
        "dataset_name": "All Datasets",
        "data_provenance": "ACADEMIC PROTOCOL",
        "metric": "data_segregation_policy",
        "value": "Strict Segregation",
        "notes": "Incident statistics and vulnerability intelligence are maintained in segregated tables."
    })

    result_df = pd.DataFrame(records)
    logging.info(f"Generated descriptive statistics summary ({len(result_df)} indicators).")
    return result_df


# =============================================================================
# 8. EXPORT RESULTS & MASTER ORCHESTRATION (SRS FR-020, FR-046)
# =============================================================================

def export_analytics_results(
    analytics_results: Dict[str, pd.DataFrame],
    output_dir: Optional[Union[Path, str]] = None
) -> Dict[str, Path]:
    """
    Export all historical analytics DataFrames to CSV files.

    Saves to:
        - Primary: output/analytics/ (for Power BI ingestion and reporting)
        - Mirror summary: data/processed/historical_analytics_summary.csv

    Uses atomic safe write to prevent corrupted files.

    Args:
        analytics_results: Dict mapping analytical name to DataFrame.
        output_dir: Destination folder (defaults to output/analytics/).

    Returns:
        Dict[str, Path]: Mapping of export keys to exported file paths.
    """
    target_dir = Path(output_dir) if output_dir else DEFAULT_OUTPUT_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    filename_map = {
        "threat_distribution": "threat_distribution.csv",
        "top_attack_types": "top_attack_types.csv",
        "severity_distribution": "severity_distribution.csv",
        "incident_trends_monthly": "incident_trends_monthly.csv",
        "incident_trends_annual": "incident_trends_annual.csv",
        "yoy_by_threat_type": "yoy_by_threat_type.csv",
        "sector_comparison": "sector_comparison.csv",
        "sector_severity_breakdown": "sector_severity_breakdown.csv",
        "top_sector_by_year": "top_sector_by_year.csv",
        "vulnerability_severity": "vulnerability_severity_summary.csv",
        "vulnerability_cvss_statistics": "vulnerability_cvss_statistics.csv",
        "vulnerability_score_distribution": "vulnerability_score_distribution.csv",
        "vulnerability_kev_summary": "vulnerability_kev_summary.csv",
        "descriptive_statistics": "descriptive_statistics_metadata.csv",
    }

    exported_files = {}

    for key, df in analytics_results.items():
        if df is None or df.empty:
            logging.warning(f"Skipping export for '{key}': DataFrame is empty.")
            continue

        filename = filename_map.get(key, f"{key}.csv")
        dest_path = target_dir / filename
        safe_write_csv(df, dest_path)
        exported_files[key] = dest_path

    # Also write combined descriptive metadata to data/processed for data-pipeline transparency
    if "descriptive_statistics" in analytics_results and not analytics_results["descriptive_statistics"].empty:
        summary_copy = PROCESSED_DATA_DIR / "analytics_summary.csv"
        safe_write_csv(analytics_results["descriptive_statistics"], summary_copy)
        exported_files["summary_copy"] = summary_copy

    logging.info(f"Exported {len(exported_files)} analytics CSV files to {target_dir}")
    return exported_files


def run_all_historical_analytics(
    data_source: Optional[Union[pd.DataFrame, sqlite3.Connection, Path, str]] = None,
    output_dir: Optional[Union[Path, str]] = None,
    export_csv: bool = True
) -> Dict[str, pd.DataFrame]:
    """
    Execute all 7 historical cybersecurity analyses and optionally export to CSV.

    Args:
        data_source: Incident data source (DataFrame, SQLite Connection, or CSV Path).
                     Defaults to database/nctirap.db.
        output_dir: Destination path for exported CSV files. Defaults to output/analytics/.
        export_csv: If True, writes results to disk using atomic CSV export.

    Returns:
        Dict[str, pd.DataFrame]: Comprehensive dictionary of all computed analytical DataFrames.
    """
    logging.info("=" * 60)
    logging.info("STARTING HISTORICAL CYBERSECURITY ANALYTICS PIPELINE")
    logging.info("=" * 60)

    results = {}

    # 1. Attack type distribution & top attack types
    df_threats = count_incidents_by_attack_type(data_source)
    results["threat_distribution"] = df_threats
    results["top_attack_types"] = identify_top_attack_types(data_source, top_n=5)

    # 2. Severity distribution
    results["severity_distribution"] = count_incidents_by_severity(data_source)

    # 3. Temporal trends & YoY changes
    monthly_trend, annual_trend = analyze_incident_trends(data_source)
    results["incident_trends_monthly"] = monthly_trend
    results["incident_trends_annual"] = annual_trend
    results["yoy_by_threat_type"] = compute_year_over_year_change(data_source)

    # 4. Sector comparative analysis
    sector_summary, sector_crosstab, top_sector_yr = compare_sectors(data_source)
    results["sector_comparison"] = sector_summary
    results["sector_severity_breakdown"] = sector_crosstab
    results["top_sector_by_year"] = top_sector_yr

    # 5. Vulnerability intelligence & CVSS scores (strictly separate from incidents)
    vuln_dict = summarize_vulnerabilities()
    if "severity_summary" in vuln_dict:
        results["vulnerability_severity"] = vuln_dict["severity_summary"]
    if "cvss_statistics" in vuln_dict:
        results["vulnerability_cvss_statistics"] = vuln_dict["cvss_statistics"]
    if "cvss_score_distribution" in vuln_dict:
        results["vulnerability_score_distribution"] = vuln_dict["cvss_score_distribution"]
    if "kev_summary" in vuln_dict:
        results["vulnerability_kev_summary"] = vuln_dict["kev_summary"]

    # 6. Comprehensive descriptive statistics and provenance metadata
    results["descriptive_statistics"] = calculate_descriptive_statistics(
        incidents_data=data_source
    )

    # 7. CSV Export
    if export_csv:
        export_analytics_results(results, output_dir=output_dir)

    logging.info("=" * 60)
    logging.info("HISTORICAL CYBERSECURITY ANALYTICS PIPELINE COMPLETED")
    logging.info("=" * 60)
    return results


# =============================================================================
# COMMAND-LINE INTERFACE
# =============================================================================

def _print_formatted_summary(results: Dict[str, pd.DataFrame]) -> None:
    """Print readable terminal tables for beginner inspection."""
    pd.set_option("display.max_columns", 8)
    pd.set_option("display.width", 100)

    print("\n" + "=" * 70)
    print("  HISTORICAL CYBERSECURITY ANALYTICS REPORT")
    print("  National Cyber Threat Intelligence & Risk Analytics Platform")
    print("=" * 70)

    # 1. Threat Distribution
    if "threat_distribution" in results and not results["threat_distribution"].empty:
        print("\n[1] Incident Attack Type Distribution:")
        print("-" * 70)
        print(results["threat_distribution"].to_string(index=False))

    # 2. Severity Breakdown
    if "severity_distribution" in results and not results["severity_distribution"].empty:
        print("\n[2] Incident Severity Counts:")
        print("-" * 70)
        print(results["severity_distribution"].to_string(index=False))

    # 3. Annual Trends & YoY Change
    if "incident_trends_annual" in results and not results["incident_trends_annual"].empty:
        print("\n[3] Annual Incident Trends & Year-over-Year (YoY) Change:")
        print("-" * 70)
        print(results["incident_trends_annual"].to_string(index=False))

    # 4. Sector Comparison
    if "sector_comparison" in results and not results["sector_comparison"].empty:
        print("\n[4] Critical Infrastructure Sector Comparison:")
        print("-" * 70)
        cols_to_show = [c for c in ["rank", "sector_name", "incident_count", "percentage", "top_threat_type"] if c in results["sector_comparison"].columns]
        print(results["sector_comparison"][cols_to_show].to_string(index=False))

    # 5. Top Sector by Year
    if "top_sector_by_year" in results and not results["top_sector_by_year"].empty:
        print("\n[5] Most Targeted Sector by Calendar Year:")
        print("-" * 70)
        print(results["top_sector_by_year"].to_string(index=False))

    # 6. Vulnerability Intelligence
    if "vulnerability_severity" in results and not results["vulnerability_severity"].empty:
        print("\n[6] Vulnerability Intelligence — Severity Summary (NVD CVEs):")
        print("-" * 70)
        print(results["vulnerability_severity"].to_string(index=False))

    if "vulnerability_cvss_statistics" in results and not results["vulnerability_cvss_statistics"].empty:
        print("\n[7] CVSS Base Score Descriptive Statistics (NVD CVEs):")
        print("-" * 70)
        print(results["vulnerability_cvss_statistics"].to_string(index=False))

    # 7. Metadata & Non-Causation Policy
    if "descriptive_statistics" in results and not results["descriptive_statistics"].empty:
        print("\n[8] Metadata, Data Provenance & Methodological Disclaimers:")
        print("-" * 70)
        print(results["descriptive_statistics"][["category", "dataset_name", "metric", "value"]].to_string(index=False))

    print("\n" + "=" * 70)
    print("  [SUCCESS] All analytics calculated and exported to output/analytics/")
    print("=" * 70 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m src.analytics",
        description="Historical Cybersecurity Analytics Module for NCTIRAP"
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Path to incident CSV file (optional; defaults to database/nctirap.db)"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Destination directory for output CSV files (default: {DEFAULT_OUTPUT_DIR})"
    )
    parser.add_argument(
        "--no-export",
        action="store_true",
        help="Compute analytics in memory without writing CSV files"
    )

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    results = run_all_historical_analytics(
        data_source=args.input,
        output_dir=args.output,
        export_csv=not args.no_export
    )

    _print_formatted_summary(results)


if __name__ == "__main__":
    main()

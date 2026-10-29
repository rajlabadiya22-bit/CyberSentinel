"""
src/risk_scoring.py — Explainable Academic Cyber Risk Scoring Module
=====================================================================
National Cyber Threat Intelligence & Risk Analytics Platform

PURPOSE:
    This module implements an explainable, transparent, and reproducible
    cyber risk scoring engine based on the Academic Cyber Risk Score (ACRS)
    and National Cyber Risk Index (NCRI) defined in SRS Section 8.4.

ACADEMIC DISCLAIMER:
    This is an ACADEMIC RISK MODEL developed for educational demonstration.
    It does NOT represent an official national security assessment, statutory
    evaluation, or government policy (e.g., CERT-In or NCIIPC mandates).
    All outputs are explicitly labeled:
        "Academic Model — Not an Official Government Metric"

MODEL ARCHITECTURE & COMPONENTS:
    ┌─────────────────────────────────────────────────────────────────────────┐
    │  COMPOSITE ACADEMIC CYBER RISK SCORE (ACRS):                            │
    │  ACRS_s = α × NIFS_s + β × WSS_s + γ × Criticality_s                    │
    │                                                                         │
    │  Where:                                                                 │
    │    α = 0.40  (weight assigned to incident frequency)                    │
    │    β = 0.40  (weight assigned to incident severity profile)             │
    │    γ = 0.20  (weight assigned to sector criticality)                    │
    │    α + β + γ = 1.00                                                     │
    │                                                                         │
    │  1. Normalised Incident Frequency Score (NIFS):                         │
    │     NIFS_s = (F_s / max(F_i)) × 100               [Range: 0 – 100]       │
    │                                                                         │
    │  2. Weighted Severity Score (WSS):                                      │
    │     WSS_raw = (4C + 3H + 2M + 1L) / (4 × Total) × 100                   │
    │     WSS_rescaled = ((WSS_raw - 25) / 75) × 100   [Range: 0 – 100]       │
    │                                                                         │
    │  3. Criticality Component:                                              │
    │     • Corrected (Normalized) Scale:                                     │
    │       NSCS_s = (SCW_s / max(SCW)) × 100          [Range: 0 – 100]       │
    │     • Literal SRS Scale:                                                │
    │       SCW_s × 100                                [Range: 0 – 20]        │
    │                                                                         │
    │  NATIONAL CYBER RISK INDEX (NCRI):                                      │
    │  NCRI = Σ (SCW_s × ACRS_s) for all sectors (excluding 'Other')          │
    └─────────────────────────────────────────────────────────────────────────┘

MATHEMATICAL CONSISTENCY ANALYSIS & CORRECTION:
    In the literal SRS Section 8.4.3 formula:
        ACRS_s = α × NIFS_s + β × WSS_s + γ × (SCW_s × 100)
    Because SCW_s represents fractional shares summing to 1.00 (where the maximum
    sector weight is Power & Energy at 0.20), the term (SCW_s × 100) can never
    exceed 20.0. Consequently, γ × (SCW_s × 100) contributes at most 0.20 × 20 = 4.0
    points out of 20 possible points.

    Under the literal formula, the theoretical maximum score for any sector is:
        Max ACRS = 0.40(100) + 0.40(100) + 0.20(20) = 84.0  (NOT 100.0)
    This creates an inconsistency with the approved Risk Categories where
    "Critical Risk" spans 75 – 100 (leaving 85 – 100 mathematically unreachable).

    PROPOSED & IMPLEMENTED CORRECTION:
    To ensure all three components occupy an identical [0, 100] scale:
        NSCS_s = (SCW_s / max(SCW)) × 100
    Where max(SCW) = 0.20. Under this normalized formulation:
        Max ACRS = 0.40(100) + 0.40(100) + 0.20(100) = 100.0
    This module computes both the Normalized ACRS (recommended) and the
    Literal SRS ACRS, documenting both side-by-side for total transparency.

APPROVED RISK CATEGORIES (SRS Section 8.4.4):
    75 – 100 : Critical Risk
    50 – 74  : High Risk
    25 – 49  : Moderate Risk
    0 – 24   : Low Risk

SRS REFERENCES:
    FR-021 (define sectors), FR-022 (NIFS), FR-023 (WSS), FR-024 (SCW),
    FR-025 (composite ACRS), FR-026 (risk classification),
    FR-027 (ranked export), FR-029 (NCRI), FR-030 (disclaimer).
"""

import argparse
import json
import logging
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "database" / "nctirap.db"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "output" / "analytics"
CONFIG_PATH = PROJECT_ROOT / "config" / "taxonomy.json"

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
# DEFAULT TAXONOMY CONFIGURATION & SECTOR ASSUMPTIONS
# =============================================================================

DEFAULT_SECTOR_CRITICALITY_WEIGHTS = {
    "Power & Energy": 0.20,
    "Banking & Finance": 0.18,
    "Telecommunications": 0.16,
    "Government Services": 0.15,
    "Healthcare": 0.13,
    "Transportation": 0.10,
    "Defence (Public Data)": 0.08,
    "Other": 0.00,
}

SECTOR_CRITICALITY_ASSUMPTIONS = {
    "Power & Energy": "Foundational physical dependency; disruption causes systemic cascading failure across grid, water, and telecom.",
    "Banking & Finance": "Financial stability and transaction integrity; high systemic economic contagion risks.",
    "Telecommunications": "Backbone of modern connectivity, Internet routing, digital payments, and emergency communications.",
    "Government Services": "Public administrative continuity, citizen identity systems, and essential civic service delivery.",
    "Healthcare": "Immediate threat to patient safety and human life upon digital system shutdown.",
    "Transportation": "Physical mobility, aviation, railway signalling, and national freight supply-chain logistics.",
    "Defence (Public Data)": "National security baseline (strictly public, open-source educational evaluation only).",
    "Other": "General unclassified entities; assigned 0.00 weight to exclude from national weighted index.",
}

SEVERITY_NUMERIC_WEIGHTS = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Unknown": 0,
}

DEFAULT_FORMULA_WEIGHTS = {
    "alpha": 0.40,  # Frequency weight
    "beta": 0.40,   # Severity weight
    "gamma": 0.20,  # Criticality weight
}


def load_taxonomy_config(config_path: Optional[Path] = None) -> dict:
    """Load taxonomy configuration from JSON file or return defaults."""
    path = config_path or CONFIG_PATH
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                # Filter out comment keys (keys starting with '_')
                if "sector_criticality_weights" in data and isinstance(data["sector_criticality_weights"], dict):
                    data["sector_criticality_weights"] = {
                        k: float(v) for k, v in data["sector_criticality_weights"].items()
                        if not k.startswith("_")
                    }
                if "acrs_formula_weights" in data and isinstance(data["acrs_formula_weights"], dict):
                    data["acrs_formula_weights"] = {
                        k: float(v) for k, v in data["acrs_formula_weights"].items()
                        if not k.startswith("_")
                    }
                return data
        except Exception as e:
            logging.warning(f"Failed to read taxonomy from {path}: {e}. Using defaults.")

    return {
        "sector_criticality_weights": DEFAULT_SECTOR_CRITICALITY_WEIGHTS,
        "acrs_formula_weights": DEFAULT_FORMULA_WEIGHTS,
        "severity_levels": SEVERITY_NUMERIC_WEIGHTS,
        "target_sectors": list(DEFAULT_SECTOR_CRITICALITY_WEIGHTS.keys()),
    }


# =============================================================================
# DATA EXTRACTION HELPERS
# =============================================================================

def _extract_incident_data(
    data: Optional[Union[pd.DataFrame, sqlite3.Connection, Path, str]] = None
) -> pd.DataFrame:
    """
    Extract incident records into a DataFrame with standardized columns.
    Accepts DataFrame, SQLite Connection, CSV Path, or defaults to database/nctirap.db.
    """
    if isinstance(data, pd.DataFrame):
        return data.copy()

    if isinstance(data, sqlite3.Connection):
        query = """
            SELECT 
                i.incident_id,
                i.incident_date,
                t.threat_type_name AS threat_type,
                s.sector_name AS target_sector,
                sev.severity_name AS severity,
                i.data_source
            FROM INCIDENTS i
            LEFT JOIN THREAT_TYPES t ON i.threat_type_fk = t.threat_type_id
            LEFT JOIN SECTORS s ON i.sector_fk = s.sector_id
            LEFT JOIN SEVERITY_LEVELS sev ON i.severity_fk = sev.severity_id
        """
        return pd.read_sql_query(query, data)

    if data is not None:
        p = Path(data)
        if p.exists():
            if p.suffix.lower() == ".db":
                conn = sqlite3.connect(str(p))
                df = _extract_incident_data(conn)
                conn.close()
                return df
            return pd.read_csv(p, encoding="utf-8")

    # Default fallback: check database then processed CSV
    if DEFAULT_DB_PATH.exists():
        try:
            conn = sqlite3.connect(str(DEFAULT_DB_PATH))
            df = _extract_incident_data(conn)
            conn.close()
            if not df.empty:
                return df
        except Exception as exc:
            logging.warning(f"Could not read from default DB: {exc}")

    csv_fallback = PROJECT_ROOT / "data" / "processed" / "incidents_cleaned.csv"
    if csv_fallback.exists():
        return pd.read_csv(csv_fallback, encoding="utf-8")

    logging.warning("No incident data found for risk scoring. Returning empty DataFrame.")
    return pd.DataFrame()


# =============================================================================
# COMPONENT 1: NORMALISED INCIDENT FREQUENCY SCORE (NIFS)
# =============================================================================

def compute_nifs(
    data: Optional[Union[pd.DataFrame, sqlite3.Connection, Path, str]] = None,
    taxonomy: Optional[dict] = None
) -> pd.DataFrame:
    """
    Compute the Normalised Incident Frequency Score (NIFS) for every sector.

    Formula:
        NIFS_s = (F_s / max(F_i)) × 100

    Guarantees:
        - If dataset has 0 incidents, returns 0.0 without division by zero.
        - Sector with highest incident count receives exactly 100.0.
        - Sectors with 0 incidents receive 0.0.
        - Preserves all sectors defined in taxonomy.

    Args:
        data: Incident dataset.
        taxonomy: Optional taxonomy dict.

    Returns:
        pd.DataFrame: Columns ['sector_name', 'incident_count', 'nifs_score']
    """
    tax = taxonomy or load_taxonomy_config()
    all_sectors = tax.get("target_sectors", list(DEFAULT_SECTOR_CRITICALITY_WEIGHTS.keys()))

    df = _extract_incident_data(data)

    sector_counts = {s: 0 for s in all_sectors}

    if not df.empty:
        col = "target_sector" if "target_sector" in df.columns else ("sector_name" if "sector_name" in df.columns else None)
        if col:
            raw_counts = df[col].dropna().value_counts().to_dict()
            for s, c in raw_counts.items():
                if s in sector_counts:
                    sector_counts[s] += c
                else:
                    sector_counts["Other"] = sector_counts.get("Other", 0) + c

    rows = [{"sector_name": s, "incident_count": count} for s, count in sector_counts.items()]
    result_df = pd.DataFrame(rows)

    max_count = result_df["incident_count"].max() if not result_df.empty else 0

    if max_count > 0:
        result_df["nifs_score"] = ((result_df["incident_count"] / max_count) * 100.0).round(2)
    else:
        result_df["nifs_score"] = 0.0

    return result_df


# =============================================================================
# COMPONENT 2: WEIGHTED SEVERITY SCORE (WSS)
# =============================================================================

def compute_wss(
    data: Optional[Union[pd.DataFrame, sqlite3.Connection, Path, str]] = None,
    taxonomy: Optional[dict] = None
) -> pd.DataFrame:
    """
    Compute the Weighted Severity Score (WSS) for each sector.

    Formulas:
        WSS_raw = (4·C + 3·H + 2·M + 1·L) / (4·(C + H + M + L)) × 100
        WSS_rescaled = ((WSS_raw - 25) / 75) × 100

    Guarantees:
        - If sector has 0 incidents, WSS_raw = 0.0 and WSS_rescaled = 0.0.
        - If 100% of incidents are Low: WSS_raw = 25.0 -> WSS_rescaled = 0.0.
        - If 100% of incidents are Critical: WSS_raw = 100.0 -> WSS_rescaled = 100.0.
        - Clipped safely to [0.0, 100.0].
        - Avoids division by zero.

    Args:
        data: Incident dataset.
        taxonomy: Optional taxonomy dict.

    Returns:
        pd.DataFrame: Columns ['sector_name', 'critical_count', 'high_count',
                               'medium_count', 'low_count', 'unknown_count',
                               'evaluated_incidents', 'wss_raw', 'wss_score']
    """
    tax = taxonomy or load_taxonomy_config()
    all_sectors = tax.get("target_sectors", list(DEFAULT_SECTOR_CRITICALITY_WEIGHTS.keys()))

    df = _extract_incident_data(data)

    records = []
    sec_col = "target_sector" if "target_sector" in df.columns else ("sector_name" if "sector_name" in df.columns else None)
    sev_col = "severity" if "severity" in df.columns else ("severity_name" if "severity_name" in df.columns else None)

    for sector in all_sectors:
        if df.empty or sec_col is None or sev_col is None:
            records.append({
                "sector_name": sector,
                "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0,
                "unknown_count": 0, "evaluated_incidents": 0, "wss_raw": 0.0, "wss_score": 0.0
            })
            continue

        sec_df = df[df[sec_col] == sector]
        sev_counts = sec_df[sev_col].astype(str).str.strip().str.capitalize().value_counts().to_dict()

        c = sev_counts.get("Critical", 0)
        h = sev_counts.get("High", 0)
        m = sev_counts.get("Medium", 0)
        l = sev_counts.get("Low", 0)
        u = sev_counts.get("Unknown", 0)

        evaluated = c + h + m + l

        if evaluated > 0:
            numerator = 4 * c + 3 * h + 2 * m + 1 * l
            denominator = 4 * evaluated
            wss_raw = round((numerator / denominator) * 100.0, 2)
            # Min-Max Rescaling from [25, 100] to [0, 100]
            wss_rescaled = round(((wss_raw - 25.0) / 75.0) * 100.0, 2)
            wss_rescaled = float(np.clip(wss_rescaled, 0.0, 100.0))
        else:
            wss_raw = 0.0
            wss_rescaled = 0.0

        records.append({
            "sector_name": sector,
            "critical_count": c,
            "high_count": h,
            "medium_count": m,
            "low_count": l,
            "unknown_count": u,
            "evaluated_incidents": evaluated,
            "wss_raw": wss_raw,
            "wss_score": wss_rescaled,
        })

    return pd.DataFrame(records)


# =============================================================================
# COMPONENT 3: SECTOR CRITICALITY (SCW & NSCS)
# =============================================================================

def compute_sector_criticality(taxonomy: Optional[dict] = None) -> pd.DataFrame:
    """
    Retrieve and normalize Sector Criticality Weights (SCW).

    Calculates:
        - scw: The raw fractional criticality weight (e.g., 0.20 for Power & Energy).
        - scw_percentage: Raw SCW × 100 (range 0.0 – 20.0).
        - nscs_score: Normalized Sector Criticality Score on a full [0, 100] scale:
                      NSCS = (SCW / max(SCW)) × 100
        - criticality_assumption: Documented academic justification.

    Returns:
        pd.DataFrame: Columns ['sector_name', 'scw', 'scw_percentage', 'nscs_score', 'assumption']
    """
    tax = taxonomy or load_taxonomy_config()
    raw_scw = tax.get("sector_criticality_weights", DEFAULT_SECTOR_CRITICALITY_WEIGHTS)
    scw_dict = {k: float(v) for k, v in raw_scw.items() if not k.startswith("_")}

    non_other_weights = [w for s, w in scw_dict.items() if s != "Other"]
    max_scw = max(non_other_weights) if non_other_weights else 0.20

    rows = []
    for sector, scw in scw_dict.items():
        scw_val = float(scw)
        scw_pct = round(scw_val * 100.0, 2)
        nscs = round((scw_val / max_scw) * 100.0, 2) if max_scw > 0 else 0.0
        nscs = float(np.clip(nscs, 0.0, 100.0))

        rows.append({
            "sector_name": sector,
            "scw": scw_val,
            "scw_percentage": scw_pct,
            "nscs_score": nscs,
            "assumption": SECTOR_CRITICALITY_ASSUMPTIONS.get(sector, "Assigned project-defined criticality weight.")
        })

    return pd.DataFrame(rows)


# =============================================================================
# RISK CATEGORIZATION HELPER
# =============================================================================

def classify_risk_category(acrs_score: float) -> str:
    """
    Assign a risk category label based on an ACRS value.

    Approved SRS Section 8.4.4 Thresholds:
        75 – 100 : Critical Risk
        50 – 74  : High Risk
        25 – 49  : Moderate Risk
        0 – 24   : Low Risk

    Raises ValueError if score is outside [0.0, 100.0].
    """
    if pd.isna(acrs_score):
        return "Unknown"

    score = float(acrs_score)
    if score < 0.0 or score > 100.0:
        raise ValueError(f"ACRS score must be between 0.0 and 100.0. Received: {acrs_score}")

    if score >= 75.0:
        return "Critical Risk"
    elif score >= 50.0:
        return "High Risk"
    elif score >= 25.0:
        return "Moderate Risk"
    else:
        return "Low Risk"


def validate_acrs_range(acrs_score: float) -> bool:
    """Verify that an ACRS score falls strictly within [0.0, 100.0]."""
    if pd.isna(acrs_score):
        return False
    return 0.0 <= float(acrs_score) <= 100.0


# =============================================================================
# CORE COMPOSITE SCORING: ACADEMIC CYBER RISK SCORE (ACRS)
# =============================================================================

def compute_sector_risk_scores(
    data: Optional[Union[pd.DataFrame, sqlite3.Connection, Path, str]] = None,
    taxonomy: Optional[dict] = None,
    normalize_criticality: bool = True
) -> List[Dict[str, Union[str, float, int]]]:
    """
    Compute the Academic Cyber Risk Score (ACRS) for every critical infrastructure sector.

    Formula implemented:
        ACRS = α · NIFS + β · WSS + γ · Criticality

    Where:
        α = 0.40, β = 0.40, γ = 0.20
        NIFS ∈ [0, 100]
        WSS  ∈ [0, 100]
        Criticality:
            - If normalize_criticality=True (Recommended): NSCS ∈ [0, 100]
            - If normalize_criticality=False (Literal SRS): SCW × 100 ∈ [0, 20]

    Both scores are retained in the output for transparent inspection.

    Args:
        data: Incident dataset (DataFrame, SQLite Connection, or CSV Path).
        taxonomy: Optional taxonomy dict.
        normalize_criticality: If True, uses the corrected full-range NSCS.

    Returns:
        List[Dict]: Ranked list of dictionaries sorted by ACRS descending.
    """
    tax = taxonomy or load_taxonomy_config()
    weights = tax.get("acrs_formula_weights", DEFAULT_FORMULA_WEIGHTS)
    alpha = float(weights.get("alpha", 0.40))
    beta = float(weights.get("beta", 0.40))
    gamma = float(weights.get("gamma", 0.20))

    # Compute the 3 components
    df_nifs = compute_nifs(data, tax)
    df_wss = compute_wss(data, tax)
    df_crit = compute_sector_criticality(tax)

    # Merge into a single master calculation table
    merged = df_nifs.merge(df_wss, on="sector_name").merge(df_crit, on="sector_name")

    results = []

    for _, row in merged.iterrows():
        s_name = row["sector_name"]
        nifs = float(row["nifs_score"])
        wss = float(row["wss_score"])
        scw = float(row["scw"])
        nscs = float(row["nscs_score"])
        scw_pct = float(row["scw_percentage"])
        cnt = int(row["incident_count"])

        # Corrected full-scale ACRS [0, 100]
        acrs_normalized = round(alpha * nifs + beta * wss + gamma * nscs, 2)
        acrs_normalized = float(np.clip(acrs_normalized, 0.0, 100.0))

        # Literal SRS ACRS [0, 84]
        acrs_literal = round(alpha * nifs + beta * wss + gamma * scw_pct, 2)
        acrs_literal = float(np.clip(acrs_literal, 0.0, 100.0))

        # Select primary ACRS based on flag
        primary_acrs = acrs_normalized if normalize_criticality else acrs_literal
        category = classify_risk_category(primary_acrs)

        # Factor contributions (explainability)
        freq_pts = round(alpha * nifs, 2)
        sev_pts = round(beta * wss, 2)
        crit_pts = round(gamma * (nscs if normalize_criticality else scw_pct), 2)

        explanation = (
            f"Frequency: {freq_pts:.1f} pts ({nifs:.1f}% rel. vol.) + "
            f"Severity: {sev_pts:.1f} pts (WSS {wss:.1f}) + "
            f"Criticality: {crit_pts:.1f} pts (SCW {scw:.2f})"
        )

        results.append({
            "sector_name": s_name,
            "incident_count": cnt,
            "nifs_score": nifs,
            "wss_raw": float(row["wss_raw"]),
            "wss_score": wss,
            "scw": scw,
            "nscs_score": nscs,
            "acrs_score": primary_acrs,
            "acrs_literal_srs_score": acrs_literal,
            "risk_category": category,
            "freq_points_contrib": freq_pts,
            "sev_points_contrib": sev_pts,
            "crit_points_contrib": crit_pts,
            "contributing_factors": explanation,
            "criticality_assumption": row["assumption"],
            "data_source": "ACADEMIC MODEL (PROCESSED INCIDENTS)"
        })

    # Sort descending by primary acrs_score
    results = sorted(results, key=lambda x: x["acrs_score"], reverse=True)

    # Assign ranks
    for idx, r in enumerate(results, start=1):
        r["rank"] = idx

    logging.info(f"Computed ACRS risk scores for {len(results)} sectors.")
    return results


# =============================================================================
# NATIONAL CYBER RISK INDEX (NCRI) (SRS Section 8.4.5)
# =============================================================================

def compute_national_risk_index(
    sector_scores: List[Dict[str, Union[str, float, int]]],
    taxonomy: Optional[dict] = None
) -> Dict[str, Union[str, float, int]]:
    """
    Compute the aggregate National Cyber Risk Index (NCRI).

    Formula:
        NCRI = Σ (SCW_s × ACRS_s) for all sectors (excluding 'Other')

    Since Σ SCW_s = 1.00, NCRI is a true weighted average across sectors.

    Args:
        sector_scores: Output from compute_sector_risk_scores().
        taxonomy: Optional taxonomy dict.

    Returns:
        Dict: Contains NCRI score, category, contributing sector weights, and disclaimers.
    """
    if not sector_scores:
        logging.warning("compute_national_risk_index: sector_scores is empty.")
        return {
            "ncri_score": 0.0,
            "ncri_label": "Unknown",
            "ncri_literal_srs_score": 0.0,
            "total_incidents": 0,
            "evaluated_sectors_count": 0,
            "analysis_date": datetime.now().strftime("%Y-%m-%d"),
            "period_label": "2021-2024",
            "disclaimer": "Academic Model — Not an Official Government Metric"
        }

    tax = taxonomy or load_taxonomy_config()
    raw_scw = tax.get("sector_criticality_weights", DEFAULT_SECTOR_CRITICALITY_WEIGHTS)
    scw_dict = {k: float(v) for k, v in raw_scw.items() if not k.startswith("_")}

    ncri_normalized = 0.0
    ncri_literal = 0.0
    total_incidents = 0
    evaluated_count = 0

    for item in sector_scores:
        s_name = item.get("sector_name")
        if s_name == "Other":
            continue  # Excluded from weighted national index as per SRS 8.4.5

        scw = float(item.get("scw", scw_dict.get(s_name, 0.0)))
        acrs = float(item.get("acrs_score", 0.0))
        acrs_lit = float(item.get("acrs_literal_srs_score", 0.0))
        cnt = int(item.get("incident_count", 0))

        ncri_normalized += scw * acrs
        ncri_literal += scw * acrs_lit
        total_incidents += cnt
        evaluated_count += 1

    ncri_normalized = round(float(np.clip(ncri_normalized, 0.0, 100.0)), 2)
    ncri_literal = round(float(np.clip(ncri_literal, 0.0, 100.0)), 2)
    category = classify_risk_category(ncri_normalized)

    logging.info(f"Computed NCRI: {ncri_normalized:.2f} ({category})")

    return {
        "ncri_score": ncri_normalized,
        "ncri_label": category,
        "ncri_literal_srs_score": ncri_literal,
        "total_incidents": total_incidents,
        "evaluated_sectors_count": evaluated_count,
        "analysis_date": datetime.now().strftime("%Y-%m-%d"),
        "period_label": "2021-2024",
        "disclaimer": "Academic Model — Not an Official Government Metric"
    }


# =============================================================================
# THREAT CATEGORY RISK SCORING (DUAL PERSPECTIVE INTELLIGENCE)
# =============================================================================

def compute_threat_category_risk_scores(
    data: Optional[Union[pd.DataFrame, sqlite3.Connection, Path, str]] = None,
    taxonomy: Optional[dict] = None
) -> List[Dict[str, Union[str, float, int]]]:
    """
    Compute Academic Threat Risk Scores (ATRS) for threat categories.

    Evaluates threat vectors along three explainable axes:
        1. Threat Frequency Score (relative to top threat vector).
        2. Threat Severity Index (proportion of Critical/High incidents).
        3. Sector Breadth (proportion of critical infrastructure sectors targeted).

    Formula:
        ATRS = 0.40 · Freq + 0.40 · Sev + 0.20 · Breadth   [Range: 0 – 100]

    Returns:
        List[Dict]: Ranked list of threat vectors by risk score.
    """
    df = _extract_incident_data(data)
    tax = taxonomy or load_taxonomy_config()
    all_sectors = set(tax.get("target_sectors", DEFAULT_SECTOR_CRITICALITY_WEIGHTS.keys())) - {"Other"}
    total_sectors = max(len(all_sectors), 1)

    if df.empty or "threat_type" not in df.columns:
        return []

    threat_counts = df["threat_type"].value_counts().to_dict()
    max_threat_count = max(threat_counts.values()) if threat_counts else 1

    results = []

    for threat, count in threat_counts.items():
        sub_df = df[df["threat_type"] == threat]

        # 1. Frequency Score (0-100)
        freq_score = round((count / max_threat_count) * 100.0, 2)

        # 2. Severity Index (0-100)
        sev_counts = sub_df["severity"].astype(str).str.strip().str.capitalize().value_counts().to_dict() if "severity" in sub_df.columns else {}
        crit = sev_counts.get("Critical", 0)
        high = sev_counts.get("High", 0)
        med = sev_counts.get("Medium", 0)
        low = sev_counts.get("Low", 0)
        tot_sev = crit + high + med + low

        if tot_sev > 0:
            raw_sev = ((4 * crit + 3 * high + 2 * med + 1 * low) / (4 * tot_sev)) * 100.0
            sev_score = round(((raw_sev - 25.0) / 75.0) * 100.0, 2)
            sev_score = float(np.clip(sev_score, 0.0, 100.0))
        else:
            sev_score = 0.0

        # 3. Sector Breadth Score (0-100)
        sec_col = "target_sector" if "target_sector" in sub_df.columns else "sector_name"
        sectors_hit = set(sub_df[sec_col].dropna().unique()) & all_sectors if sec_col in sub_df.columns else set()
        breadth_score = round((len(sectors_hit) / total_sectors) * 100.0, 2)

        # Composite Threat Risk Score
        atrs = round(0.40 * freq_score + 0.40 * sev_score + 0.20 * breadth_score, 2)
        atrs = float(np.clip(atrs, 0.0, 100.0))
        category = classify_risk_category(atrs)

        results.append({
            "threat_type": threat,
            "incident_count": count,
            "frequency_score": freq_score,
            "severity_score": sev_score,
            "sectors_targeted_count": len(sectors_hit),
            "sector_breadth_score": breadth_score,
            "threat_risk_score": atrs,
            "threat_risk_category": category,
            "contributing_factors": f"Freq: {freq_score:.1f} | Sev: {sev_score:.1f} | Sectors: {len(sectors_hit)}/{total_sectors}",
            "disclaimer": "Academic Threat Model"
        })

    results = sorted(results, key=lambda x: x["threat_risk_score"], reverse=True)
    for idx, r in enumerate(results, start=1):
        r["rank"] = idx

    logging.info(f"Computed threat category risk scores for {len(results)} threat types.")
    return results


# =============================================================================
# EXPORT & REPORTING FUNCTIONS
# =============================================================================

def export_risk_model_outputs(
    sector_scores: List[Dict],
    ncri_result: Dict,
    threat_scores: Optional[List[Dict]] = None,
    output_dir: Optional[Union[Path, str]] = None
) -> Dict[str, Path]:
    """
    Export all risk scoring outputs and methodology manifests to CSV files.

    Target Directory: output/analytics/ (Power BI source folder).
    Uses atomic writing to prevent file corruption.

    Returns:
        Dict[str, Path]: Mapping of export keys to saved file paths.
    """
    target_dir = Path(output_dir) if output_dir else DEFAULT_OUTPUT_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    saved_files = {}

    # 1. Sector Risk Scores
    if sector_scores:
        df_sec = pd.DataFrame(sector_scores)
        p_sec = target_dir / "sector_risk_scores.csv"
        safe_write_csv(df_sec, p_sec)
        saved_files["sector_risk_scores"] = p_sec

    # 2. National Risk Index
    if ncri_result:
        df_ncri = pd.DataFrame([ncri_result])
        p_ncri = target_dir / "national_risk_index.csv"
        safe_write_csv(df_ncri, p_ncri)
        saved_files["national_risk_index"] = p_ncri

    # 3. Threat Category Risk Scores
    if threat_scores:
        df_thr = pd.DataFrame(threat_scores)
        p_thr = target_dir / "threat_risk_scores.csv"
        safe_write_csv(df_thr, p_thr)
        saved_files["threat_risk_scores"] = p_thr

    # 4. Methodology & Assumptions Manifest
    doc_rows = [
        {"parameter": "model_name", "value": "Academic Cyber Risk Score (ACRS)", "notes": "Composite sector risk metric"},
        {"parameter": "national_index_name", "value": "National Cyber Risk Index (NCRI)", "notes": "Sector Criticality Weighted National Score"},
        {"parameter": "frequency_weight_alpha", "value": "0.40", "notes": "Relative volume weight"},
        {"parameter": "severity_weight_beta", "value": "0.40", "notes": "Severity profile weight"},
        {"parameter": "criticality_weight_gamma", "value": "0.20", "notes": "Sector dependency weight"},
        {"parameter": "category_critical_risk", "value": "75 - 100", "notes": "Severe threat activity and high criticality"},
        {"parameter": "category_high_risk", "value": "50 - 74", "notes": "Elevated threat activity"},
        {"parameter": "category_moderate_risk", "value": "25 - 49", "notes": "Moderate threat activity"},
        {"parameter": "category_low_risk", "value": "0 - 24", "notes": "Low threat activity"},
        {"parameter": "statutory_disclaimer", "value": "Academic Model Only", "notes": "Not an official government or regulatory metric"}
    ]
    p_doc = target_dir / "risk_model_documentation.csv"
    safe_write_csv(pd.DataFrame(doc_rows), p_doc)
    saved_files["risk_model_documentation"] = p_doc

    logging.info(f"Successfully exported {len(saved_files)} risk model CSV files to {target_dir}")
    return saved_files


# =============================================================================
# COMMAND-LINE INTERFACE & EXECUTION RUNNER
# =============================================================================

def execute_risk_scoring_pipeline(
    data_source: Optional[Union[pd.DataFrame, sqlite3.Connection, Path, str]] = None,
    output_dir: Optional[Union[Path, str]] = None,
    save_to_db: bool = True,
    normalize_criticality: bool = True
) -> Tuple[List[Dict], Dict, List[Dict]]:
    """
    End-to-end runner: computes ACRS, NCRI, threat scores, exports CSVs, and stores to database.
    """
    taxonomy = load_taxonomy_config()

    logging.info("=" * 65)
    logging.info("NCTIRAP RISK SCORING ENGINE STARTED")
    logging.info("=" * 65)

    # 1. Sector risk scores
    sector_scores = compute_sector_risk_scores(
        data=data_source,
        taxonomy=taxonomy,
        normalize_criticality=normalize_criticality
    )

    # 2. National risk index
    ncri_result = compute_national_risk_index(sector_scores, taxonomy)

    # 3. Threat category risk scores
    threat_scores = compute_threat_category_risk_scores(data_source, taxonomy)

    # 4. Save to database if connected
    if save_to_db and DEFAULT_DB_PATH.exists():
        try:
            conn = sqlite3.connect(str(DEFAULT_DB_PATH))
            from src.database import save_sector_risk_scores, save_national_risk_index
            save_sector_risk_scores(conn, sector_scores)
            save_national_risk_index(conn, ncri_result["ncri_score"], ncri_result["period_label"])
            conn.close()
        except Exception as e:
            logging.warning(f"Could not persist risk scores to database: {e}")

    # 5. Export to CSV
    export_risk_model_outputs(sector_scores, ncri_result, threat_scores, output_dir=output_dir)

    logging.info("=" * 65)
    logging.info(f"RISK SCORING COMPLETED: NCRI = {ncri_result['ncri_score']:.2f} ({ncri_result['ncri_label']})")
    logging.info("=" * 65)

    return sector_scores, ncri_result, threat_scores


def print_risk_report(sector_scores: List[Dict], ncri_result: Dict, threat_scores: List[Dict]) -> None:
    """Print an explainable, beginner-friendly report to the console."""
    print("\n" + "=" * 75)
    print("  EXPLAINABLE NATIONAL CYBER RISK SCORING REPORT")
    print("  National Cyber Threat Intelligence & Risk Analytics Platform")
    print("  [ Academic Model - Not an Official Government Metric ]")
    print("=" * 75)

    # NCRI Summary Banner
    print(f"\n>>> NATIONAL CYBER RISK INDEX (NCRI): {ncri_result['ncri_score']:.2f} / 100.00")
    print(f">>> National Risk Category          : {ncri_result['ncri_label'].upper()}")
    print(f">>> Literal SRS Formula NCRI        : {ncri_result['ncri_literal_srs_score']:.2f}")
    print(f">>> Analysis Period                 : {ncri_result['period_label']} (Evaluated {ncri_result['total_incidents']:,} incidents across {ncri_result['evaluated_sectors_count']} sectors)")
    print("-" * 75)

    # Sector Rankings Table
    print("\n[1] CRITICAL INFRASTRUCTURE SECTOR RISK RANKINGS (ACRS):")
    print("-" * 75)
    sec_df = pd.DataFrame(sector_scores)[[
        "rank", "sector_name", "incident_count", "nifs_score", "wss_score",
        "scw", "acrs_score", "risk_category"
    ]]
    sec_df.columns = ["Rank", "Sector", "Incidents", "NIFS (Freq)", "WSS (Sev)", "SCW", "ACRS Score", "Risk Category"]
    print(sec_df.to_string(index=False))

    # Factor Explainability Breakdown
    print("\n[2] CONTRIBUTING FACTOR EXPLAINABILITY (Why sectors scored as they did):")
    print("-" * 75)
    for s in sector_scores:
        print(f"  #{s['rank']} {s['sector_name']:<22} | ACRS: {s['acrs_score']:>5.2f} ({s['risk_category']:<13})")
        print(f"      |-- {s['contributing_factors']}")
        print(f"      |-- Rationale: {s['criticality_assumption']}")

    # Threat Vector Rankings
    if threat_scores:
        print("\n[3] THREAT CATEGORY RISK SCORES (Dual-Perspective Analysis):")
        print("-" * 75)
        thr_df = pd.DataFrame(threat_scores)[[
            "rank", "threat_type", "incident_count", "frequency_score", "severity_score",
            "sectors_targeted_count", "threat_risk_score", "threat_risk_category"
        ]]
        thr_df.columns = ["Rank", "Threat Type", "Incidents", "Freq Score", "Sev Score", "Sectors Hit", "Risk Score", "Category"]
        print(thr_df.to_string(index=False))

    print("\n" + "=" * 75)
    print("  [SUCCESS] Risk scoring completed. Reports saved to output/analytics/")
    print("=" * 75 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m src.risk_scoring",
        description="Explainable National Cyber Risk Scoring Module for NCTIRAP"
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Path to incident dataset CSV (optional; defaults to database/nctirap.db)"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Destination directory for CSV outputs (default: {DEFAULT_OUTPUT_DIR})"
    )
    parser.add_argument(
        "--literal-srs",
        action="store_true",
        help="Use literal unrescaled SRS formula (capped at 84.0) instead of normalized formula"
    )
    parser.add_argument(
        "--no-db",
        action="store_true",
        help="Do not save risk scores to the SQLite database"
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    sec_scores, ncri, thr_scores = execute_risk_scoring_pipeline(
        data_source=args.input,
        output_dir=args.output,
        save_to_db=not args.no_db,
        normalize_criticality=not args.literal_srs
    )

    print_risk_report(sec_scores, ncri, thr_scores)


if __name__ == "__main__":
    main()

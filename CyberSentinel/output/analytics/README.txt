OUTPUT/ANALYTICS — Power BI Data Source Directory
===================================================

⭐ CONNECT MICROSOFT POWER BI TO THIS FOLDER ⭐

CSV files in this folder are the analytical outputs produced by src/analytics.py.
They are ready for direct consumption by Microsoft Power BI or downstream reporting.

HISTORICAL ANALYTICS CSV FILES:
──────────────────────────────────────────────────────────────────────────────
  threat_distribution.csv             ← Breakdown of incidents by attack/threat type
                                         Columns: rank, threat_type, incident_count,
                                                  percentage, cumulative_percentage, data_source

  top_attack_types.csv                ← Top 5 most frequent attack types (SRS FR-016)
                                         Columns: rank, threat_type, incident_count,
                                                  percentage, cumulative_percentage, data_source

  severity_distribution.csv           ← Breakdown of incidents by severity category
                                         Columns: severity, incident_count, percentage, data_source

  incident_trends_monthly.csv         ← Monthly incident frequency time-series
                                         Columns: year, month, month_label, incident_count, data_source

  incident_trends_annual.csv          ← Annual incident counts with Year-over-Year (YoY) change
                                         Columns: year, incident_count, count_previous_year,
                                                  yoy_change_absolute, yoy_change_pct, data_source

  yoy_by_threat_type.csv              ← Threat-type specific YoY percentage change (SRS FR-017)
                                         Columns: threat_type, year, count_this_year,
                                                  count_last_year, yoy_change_pct, data_source

  sector_comparison.csv               ← Comparative volume and primary threat by sector
                                         Columns: rank, sector_name, incident_count,
                                                  percentage, top_threat_type, data_source

  sector_severity_breakdown.csv       ← Sector by severity cross-tabulation matrix
                                         Columns: sector_name, Critical, High, Medium, Low, Total

  top_sector_by_year.csv              ← Most targeted critical sector per calendar year (SRS FR-018)
                                         Columns: year, top_sector, incident_count,
                                                  total_year_incidents, sector_pct_of_year, data_source

  vulnerability_severity_summary.csv  ← Public CVE severity breakdown (Critical/High/Medium/Low)
                                         Columns: cvss_severity, vulnerability_count, percentage, data_source

  vulnerability_cvss_statistics.csv   ← Descriptive statistics of CVSS base scores
                                         Columns: metric, value, data_source (mean, median, IQR, std)

  vulnerability_score_distribution.csv← Binned distribution by standard NIST CVSS v3 score ranges
                                         Columns: cvss_score_range, vulnerability_count, percentage

  vulnerability_kev_summary.csv       ← CISA KEV exploitation and ransomware campaign usage
                                         Columns: metric, value, data_source

  descriptive_statistics_metadata.csv ← Complete metadata log, temporal ranges, data provenance,
                                         and non-causation policy statements.

EXPLAINABLE RISK SCORING EXPORTS (STAGE 4):
──────────────────────────────────────────────────────────────────────────────
  sector_risk_scores.csv              ← Academic Cyber Risk Score (ACRS) per sector
                                         Columns: sector_name, incident_count, nifs_score, wss_raw,
                                                  wss_score, scw, nscs_score, acrs_score,
                                                  acrs_literal_srs_score, risk_category,
                                                  freq_points_contrib, sev_points_contrib,
                                                  crit_points_contrib, contributing_factors,
                                                  criticality_assumption, data_source, rank

  national_risk_index.csv             ← National Cyber Risk Index (NCRI) composite summary
                                         Columns: ncri_score, ncri_label, ncri_literal_srs_score,
                                                  total_incidents, evaluated_sectors_count,
                                                  analysis_date, period_label, disclaimer

  threat_risk_scores.csv              ← Threat category risk scores & sector breadth analysis
                                         Columns: threat_type, incident_count, frequency_score,
                                                  severity_score, sectors_targeted_count,
                                                  sector_breadth_score, threat_risk_score,
                                                  threat_risk_category, contributing_factors, rank

  risk_model_documentation.csv        ← Complete methodology, weights, thresholds & academic disclaimers
                                         Columns: parameter, value, notes

ACADEMIC DISCLAIMER:
──────────────────────────────────────────────────────────────────────────────
All data labeled "SYNTHETIC" represents simulated academic baseline data based on
CERT-In public annual reporting statistics. All data labeled "PUBLIC" represents
official public records from NIST NVD and CISA KEV.
Statistical frequencies reflect sample observations and do NOT prove causation.

-- =============================================================================
-- NCTIRAP Relational Database Schema
-- National Cyber Threat Intelligence & Risk Analytics Platform
-- File: database/schema.sql
-- Version: 2.0
--
-- PURPOSE:
--   Defines the complete relational SQLite database structure for NCTIRAP.
--   Enforces primary keys, foreign keys, constraints, and audit trails.
--   Supports incidents, sectors, attack types, regions, vulnerabilities,
--   data sources, and computed academic risk scores.
--
-- ACADEMIC DISCLAIMER:
--   This database stores data for an academic prototype. All risk scores
--   and sector criticality weights are academic models, not official
--   government national security assessments.
--
-- HOW TO RUN:
--   Via Python initialization script:
--     python src/init_database.py
--   Or manually with SQLite CLI:
--     sqlite3 database/nctirap.db < database/schema.sql
-- =============================================================================

-- Enforce foreign key constraints in SQLite
PRAGMA foreign_keys = ON;

-- =============================================================================
-- TABLE 1: ATTACK_TYPES
-- Controlled taxonomy of cyber attack and threat vectors.
-- Seeded from config/taxonomy.json.
-- =============================================================================
CREATE TABLE IF NOT EXISTS ATTACK_TYPES (
    attack_type_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_type_name TEXT    NOT NULL UNIQUE,
    description      TEXT
);

-- Backward compatibility view for legacy queries expecting THREAT_TYPES
CREATE VIEW IF NOT EXISTS THREAT_TYPES AS
SELECT 
    attack_type_id   AS threat_type_id,
    attack_type_name AS threat_type_name,
    attack_type_id,
    attack_type_name,
    description
FROM ATTACK_TYPES;

-- =============================================================================
-- TABLE 2: SECTORS
-- Critical infrastructure sectors and their Sector Criticality Weights (SCW).
-- SCW represents academic systemic dependency share (sum = 1.00 excluding 'Other').
-- =============================================================================
CREATE TABLE IF NOT EXISTS SECTORS (
    sector_id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    sector_name               TEXT    NOT NULL UNIQUE,
    sector_criticality_weight REAL    NOT NULL DEFAULT 0.0 CHECK(sector_criticality_weight >= 0.0 AND sector_criticality_weight <= 1.0),
    description               TEXT
);

-- =============================================================================
-- TABLE 3: SEVERITY_LEVELS
-- Standardized severity classifications with scoring weights for WSS formula.
-- Critical=4, High=3, Medium=2, Low=1, Unknown=0.
-- =============================================================================
CREATE TABLE IF NOT EXISTS SEVERITY_LEVELS (
    severity_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    severity_name   TEXT    NOT NULL UNIQUE,
    severity_weight INTEGER NOT NULL DEFAULT 1 CHECK(severity_weight >= 0 AND severity_weight <= 4)
);

-- =============================================================================
-- TABLE 4: REGIONS
-- Controlled lookup of Indian States, Union Territories, and National scopes.
-- Seeded from config/taxonomy.json.
-- =============================================================================
CREATE TABLE IF NOT EXISTS REGIONS (
    region_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    region_name TEXT    NOT NULL UNIQUE,
    region_type TEXT    NOT NULL DEFAULT 'State' CHECK(region_type IN ('State', 'Union Territory', 'National', 'Multiple States', 'Unknown'))
);

-- =============================================================================
-- TABLE 5: DATA_SOURCES
-- Provenance and metadata registry for datasets ingested into NCTIRAP.
-- Distinguishes public government repositories from calibrated synthetic data.
-- =============================================================================
CREATE TABLE IF NOT EXISTS DATA_SOURCES (
    data_source_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_code    TEXT    NOT NULL UNIQUE,
    source_name    TEXT    NOT NULL,
    source_type    TEXT    NOT NULL CHECK(source_type IN ('PUBLIC', 'SYNTHETIC')),
    publisher      TEXT,
    url            TEXT,
    description    TEXT
);

-- =============================================================================
-- TABLE 6: INCIDENTS
-- Primary entity storing cleaned, validated historical cybersecurity incidents.
-- Enforces natural key uniqueness on incident_id to prevent duplicate ingestion.
-- =============================================================================
CREATE TABLE IF NOT EXISTS INCIDENTS (
    incident_pk        INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id        TEXT    NOT NULL UNIQUE,
    incident_date      TEXT    NOT NULL,
    attack_type_fk     INTEGER NOT NULL,
    threat_type_fk     INTEGER,
    sector_fk          INTEGER NOT NULL,
    severity_fk        INTEGER NOT NULL,
    region_fk          INTEGER,
    data_source_fk     INTEGER,
    target_state       TEXT,
    financial_loss_inr REAL,
    resolution_days    INTEGER,
    description        TEXT,
    data_source        TEXT    NOT NULL CHECK(data_source IN ('PUBLIC', 'SYNTHETIC')),
    synthetic_basis    TEXT,
    created_at         TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (attack_type_fk) REFERENCES ATTACK_TYPES(attack_type_id),
    FOREIGN KEY (threat_type_fk) REFERENCES ATTACK_TYPES(attack_type_id),
    FOREIGN KEY (sector_fk)      REFERENCES SECTORS(sector_id),
    FOREIGN KEY (severity_fk)    REFERENCES SEVERITY_LEVELS(severity_id),
    FOREIGN KEY (region_fk)      REFERENCES REGIONS(region_id),
    FOREIGN KEY (data_source_fk) REFERENCES DATA_SOURCES(data_source_id)
);

CREATE INDEX IF NOT EXISTS idx_incidents_date   ON INCIDENTS(incident_date);
CREATE INDEX IF NOT EXISTS idx_incidents_sector ON INCIDENTS(sector_fk);
CREATE INDEX IF NOT EXISTS idx_incidents_attack ON INCIDENTS(attack_type_fk);
CREATE INDEX IF NOT EXISTS idx_incidents_region ON INCIDENTS(region_fk);

-- =============================================================================
-- TABLE 7: VULNERABILITIES
-- Disclosed software vulnerabilities from NIST NVD and CISA KEV catalog.
-- Enforces natural key uniqueness on cve_id to prevent duplicate ingestion.
-- =============================================================================
CREATE TABLE IF NOT EXISTS VULNERABILITIES (
    vulnerability_pk     INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id               TEXT    NOT NULL UNIQUE,
    published_date       TEXT    NOT NULL,
    last_modified_date   TEXT,
    cvss_base_score      REAL    NOT NULL CHECK(cvss_base_score >= 0.0 AND cvss_base_score <= 10.0),
    cvss_severity        TEXT    NOT NULL CHECK(cvss_severity IN ('Critical', 'High', 'Medium', 'Low', 'Unknown')),
    cvss_vector          TEXT,
    cwe_ids              TEXT,
    vendor               TEXT,
    product              TEXT,
    vulnerability_name   TEXT,
    is_known_exploited   INTEGER NOT NULL DEFAULT 0 CHECK(is_known_exploited IN (0, 1)),
    known_ransomware_use TEXT    DEFAULT 'Unknown',
    description          TEXT,
    data_source_fk       INTEGER,
    data_source          TEXT    NOT NULL DEFAULT 'PUBLIC' CHECK(data_source IN ('PUBLIC', 'SYNTHETIC')),
    created_at           TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (data_source_fk) REFERENCES DATA_SOURCES(data_source_id)
);

CREATE INDEX IF NOT EXISTS idx_vuln_severity  ON VULNERABILITIES(cvss_severity);
CREATE INDEX IF NOT EXISTS idx_vuln_score     ON VULNERABILITIES(cvss_base_score);
CREATE INDEX IF NOT EXISTS idx_vuln_date      ON VULNERABILITIES(published_date);
CREATE INDEX IF NOT EXISTS idx_vuln_exploited ON VULNERABILITIES(is_known_exploited);

-- Backward compatibility view for legacy queries expecting CVE_RECORDS
CREATE VIEW IF NOT EXISTS CVE_RECORDS AS
SELECT 
    vulnerability_pk AS cve_pk,
    cve_id,
    published_date,
    cvss_base_score,
    cvss_severity,
    vendor,
    product,
    description
FROM VULNERABILITIES;

-- =============================================================================
-- TABLE 8: ANALYTICS_SECTOR_RISK
-- Persists computed Academic Cyber Risk Score (ACRS) per sector per pipeline run.
-- =============================================================================
CREATE TABLE IF NOT EXISTS ANALYTICS_SECTOR_RISK (
    risk_pk       INTEGER PRIMARY KEY AUTOINCREMENT,
    sector_fk     INTEGER NOT NULL,
    analysis_date TEXT    NOT NULL,
    nifs_score    REAL    NOT NULL,
    wss_score     REAL    NOT NULL,
    acrs_score    REAL    NOT NULL,
    risk_category TEXT    NOT NULL CHECK(risk_category IN ('Critical Risk', 'High Risk', 'Moderate Risk', 'Low Risk')),
    FOREIGN KEY (sector_fk) REFERENCES SECTORS(sector_id)
);

-- =============================================================================
-- TABLE 9: ANALYTICS_NATIONAL_RISK
-- Persists computed National Cyber Risk Index (NCRI) per time period.
-- =============================================================================
CREATE TABLE IF NOT EXISTS ANALYTICS_NATIONAL_RISK (
    national_risk_pk INTEGER PRIMARY KEY AUTOINCREMENT,
    period_label     TEXT    NOT NULL,
    ncri_score       REAL    NOT NULL CHECK(ncri_score >= 0.0 AND ncri_score <= 100.0),
    analysis_date    TEXT    NOT NULL
);

-- =============================================================================
-- SEED DATA: Populating Lookup Tables
-- Idempotent: INSERT OR IGNORE statements safely re-run without duplication.
-- =============================================================================

-- 1. Attack Types
INSERT OR IGNORE INTO ATTACK_TYPES (attack_type_name, description) VALUES
    ('Ransomware',           'Extortion attack utilizing malicious encryption of critical operational or enterprise data.'),
    ('Phishing',             'Social engineering vector seeking to harvest credentials or deliver payloads via deception.'),
    ('DDoS',                 'Distributed Denial of Service saturating network bandwidth or compute availability.'),
    ('Data Breach',          'Unauthorized exfiltration or exposure of confidential, personal, or operational records.'),
    ('Malware',              'Generic malicious software binaries, trojans, worms, or droppers compromising systems.'),
    ('SQL Injection',        'Injection vulnerability manipulating backend database queries via unvalidated inputs.'),
    ('Zero-Day Exploit',     'Exploitation of undisclosed, unpatched software vulnerabilities prior to vendor remediation.'),
    ('Supply Chain Attack',  'Compromise through third-party vendor software updates, libraries, or service providers.'),
    ('Insider Threat',       'Misuse of authorized internal credentials or deliberate sabotage by authorized actors.'),
    ('Social Engineering',   'Psychological manipulation of authorized personnel to bypass security controls.'),
    ('Other',                'Miscellaneous or unclassified cyber threat categories.');

-- 2. Infrastructure Sectors & SCW Values (Academic Estimates)
INSERT OR IGNORE INTO SECTORS (sector_name, sector_criticality_weight, description) VALUES
    ('Power & Energy',        0.20, 'Foundational physical dependency; disruption causes cascading failure across national grid and utilities.'),
    ('Banking & Finance',     0.18, 'Financial transaction integrity and systemic macroeconomic contagion stability.'),
    ('Telecommunications',    0.16, 'Backbone of national internet routing, digital public infrastructure, and emergency networks.'),
    ('Government Services',   0.15, 'Administrative continuity, public citizen registries (Aadhaar/UIDAI), and civic service delivery.'),
    ('Healthcare',            0.13, 'Immediate patient safety, medical telemetry, clinical triage, and hospital continuity.'),
    ('Transportation',        0.10, 'Aviation traffic management, railway signalling networks, and national freight supply-chains.'),
    ('Defence (Public Data)', 0.08, 'Public-domain military and national defence infrastructure (academic analysis only).'),
    ('Other',                 0.00, 'General commercial and unclassified entities excluded from weighted national risk index.');

-- 3. Severity Levels & Scoring Weights
INSERT OR IGNORE INTO SEVERITY_LEVELS (severity_name, severity_weight) VALUES
    ('Critical', 4),
    ('High',     3),
    ('Medium',   2),
    ('Low',      1),
    ('Unknown',  0);

-- 4. Data Sources Metadata
INSERT OR IGNORE INTO DATA_SOURCES (source_code, source_name, source_type, publisher, url, description) VALUES
    ('CERT_IN_SYNTHETIC', 'CERT-In Public Annual Report Baseline', 'SYNTHETIC', 'Indian Computer Emergency Response Team (CERT-In) / Academic Model', 'https://www.cert-in.org.in/', 'Academic synthetic dataset statistically calibrated against incident proportions published in CERT-In Annual Reports.'),
    ('NIST_NVD',          'National Vulnerability Database (NVD)', 'PUBLIC',    'National Institute of Standards and Technology (NIST), USA',              'https://nvd.nist.gov/',               'Authoritative public repository of standards-based vulnerability management data conforming to CVSS v3.x standards.'),
    ('CISA_KEV',          'Known Exploited Vulnerabilities Catalog', 'PUBLIC',  'Cybersecurity and Infrastructure Security Agency (CISA), USA',            'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'Authoritative list of vulnerabilities actively exploited in the wild by threat actors, including ransomware usage.');

-- 5. Indian States, Union Territories & Geographic Scopes
INSERT OR IGNORE INTO REGIONS (region_name, region_type) VALUES
    ('Andhra Pradesh', 'State'),
    ('Arunachal Pradesh', 'State'),
    ('Assam', 'State'),
    ('Bihar', 'State'),
    ('Chhattisgarh', 'State'),
    ('Goa', 'State'),
    ('Gujarat', 'State'),
    ('Haryana', 'State'),
    ('Himachal Pradesh', 'State'),
    ('Jharkhand', 'State'),
    ('Karnataka', 'State'),
    ('Kerala', 'State'),
    ('Madhya Pradesh', 'State'),
    ('Maharashtra', 'State'),
    ('Manipur', 'State'),
    ('Meghalaya', 'State'),
    ('Mizoram', 'State'),
    ('Nagaland', 'State'),
    ('Odisha', 'State'),
    ('Punjab', 'State'),
    ('Rajasthan', 'State'),
    ('Sikkim', 'State'),
    ('Tamil Nadu', 'State'),
    ('Telangana', 'State'),
    ('Tripura', 'State'),
    ('Uttar Pradesh', 'State'),
    ('Uttarakhand', 'State'),
    ('West Bengal', 'State'),
    ('Andaman and Nicobar Islands', 'Union Territory'),
    ('Chandigarh', 'Union Territory'),
    ('Dadra and Nagar Haveli and Daman and Diu', 'Union Territory'),
    ('Delhi', 'Union Territory'),
    ('Jammu and Kashmir', 'Union Territory'),
    ('Ladakh', 'Union Territory'),
    ('Lakshadweep', 'Union Territory'),
    ('Puducherry', 'Union Territory'),
    ('Multiple States', 'Multiple States'),
    ('National', 'National'),
    ('Unknown', 'Unknown');

-- =============================================================================
-- End of schema.sql
-- =============================================================================

DATA/RAW — Input Data Directory
================================

Place your raw cyber incident CSV or Excel files here before running the pipeline.

REQUIRED CSV COLUMN FORMAT
───────────────────────────
Your CSV file MUST contain these columns (column names are case-sensitive):

  Column Name           | Type     | Required | Description
  ──────────────────────|──────────|──────────|──────────────────────────────────────
  incident_id           | Text     | YES      | A unique ID for each incident.
                        |          |          | Example: INC-2023-00142
  incident_date         | Date     | YES      | Date the incident occurred.
                        |          |          | Accepted formats: YYYY-MM-DD, DD/MM/YYYY
  threat_type           | Text     | YES      | Type of cyber attack.
                        |          |          | See allowed values below.
  target_sector         | Text     | YES      | The targeted sector.
                        |          |          | See allowed values below.
  severity              | Text     | YES      | How severe the incident was.
                        |          |          | Allowed: Critical, High, Medium, Low
  data_source           | Text     | YES      | Must be "PUBLIC" or "SYNTHETIC".
                        |          |          | Use SYNTHETIC for your own made-up data.
  target_state          | Text     | no       | Indian state/region name. Optional.
  financial_loss_inr    | Number   | no       | Estimated loss in Rupees. Optional.
  resolution_days       | Integer  | no       | Days taken to fix the incident. Optional.
  description           | Text     | no       | Brief description. Optional.

ALLOWED THREAT TYPES (from config/taxonomy.json)
─────────────────────────────────────────────────
  Ransomware, Phishing, DDoS, Data Breach, Malware,
  SQL Injection, Zero-Day Exploit, Supply Chain Attack,
  Insider Threat, Social Engineering, Other

ALLOWED TARGET SECTORS
───────────────────────
  Power & Energy, Telecommunications, Banking & Finance,
  Government Services, Healthcare, Transportation,
  Defence (Public Data), Other

EXAMPLE CSV (first 3 rows)
───────────────────────────
incident_id,incident_date,threat_type,target_sector,severity,data_source,target_state
INC-2022-001,2022-03-15,Ransomware,Healthcare,Critical,PUBLIC,Maharashtra
INC-2022-002,2022-04-02,Phishing,Banking & Finance,High,PUBLIC,Delhi
INC-2022-003,2022-04-10,DDoS,Telecommunications,High,PUBLIC,Unknown

WHERE TO GET REAL PUBLIC DATA
──────────────────────────────
Option 1: CERT-In Annual Reports (cert-in.org.in)
  - Download the annual cybersecurity report PDF.
  - Manually extract incident statistics into a CSV with the above format.
  - Mark data_source as "PUBLIC".

Option 2: Use synthetic data for testing
  - See data/synthetic/synthetic_incidents.csv for a ready-made example.
  - Mark data_source as "SYNTHETIC".

IMPORTANT
──────────
- Do NOT include personally identifiable information (PII) such as
  individual names, email addresses, or phone numbers.
- The system will REJECT files missing the required columns.
- Files with wrong column names will be logged as errors.

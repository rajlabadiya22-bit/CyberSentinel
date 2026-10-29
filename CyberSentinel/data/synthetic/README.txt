DATA/SYNTHETIC — Demo and Testing Data Directory
==================================================

⚠️ IMPORTANT ACADEMIC DISCLAIMER ⚠️
All files in this folder contain SYNTHETIC DATA.
Synthetic data is artificially created for testing and demonstration purposes.
It does NOT represent real cyber incidents or real attack data.
Every record has data_source = "SYNTHETIC" to make this clear.

PURPOSE OF THIS FOLDER
───────────────────────
- Provides ready-made test data so you can run the pipeline immediately
  without needing real incident data.
- Used during development to test all pipeline stages.
- Can be used in your project demonstration to show the system works.

FILES IN THIS FOLDER
─────────────────────
(Files will be added in Stage 2 when implementation begins)

  synthetic_incidents.csv    ← Synthetic cyber incident records (coming in Stage 2)
  synthetic_cve_sample.csv   ← Synthetic CVE-like records (coming in Stage 3)

HOW SYNTHETIC DATA WAS CREATED
────────────────────────────────
The synthetic data in this folder was created by:
1. Choosing realistic-sounding values from the controlled vocabulary
   (e.g., sector names, threat types, severity levels).
2. Generating random dates within a defined time range.
3. Assigning data_source = "SYNTHETIC" to every single record.

The data does NOT claim to match real statistics from CERT-In or any
other official source. Numbers and distributions are illustrative only.

HOW TO USE
───────────
To run the pipeline with synthetic data:
  python main.py --input data/synthetic/synthetic_incidents.csv

⚠️ REMINDER: Do NOT present synthetic data analysis results as real findings.
Always disclose that you used synthetic data in your project report and presentation.

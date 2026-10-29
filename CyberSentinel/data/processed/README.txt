DATA/PROCESSED — Cleaned Data Output Directory
===============================================

This folder is used to save intermediate cleaned DataFrames during the pipeline.

HOW IT IS USED
───────────────
After data/raw/ files are cleaned by the pipeline, the cleaned data is:
  1. Stored permanently in the SQLite database (nctirap.db).
  2. Optionally saved here as a CSV for inspection and debugging.

You can open these files in Excel or a text editor to check that the
cleaning step worked correctly (e.g., dates are in YYYY-MM-DD format,
all threat types are from the controlled vocabulary, etc.).

FILES CREATED HERE
───────────────────
(Created automatically by the pipeline when it runs)

  cleaned_incidents.csv   ← All incident records after cleaning (Stage 2+)

THIS FOLDER IS NOT USED BY POWER BI
──────────────────────────────────────
Power BI reads from output/analytics/ — NOT from this folder.
This folder is only for your own inspection and debugging purposes.

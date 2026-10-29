LOGS — Pipeline Log Files Directory
=====================================

Log files are saved here automatically every time you run the pipeline.
If something goes wrong, check these files first.

FILES IN THIS DIRECTORY
────────────────────────
(Created automatically after first pipeline run)

  run_log.txt       ← Records every step of the pipeline.
                       Each line shows: timestamp | level | message.
                       Example:
                         2026-10-25 12:30:05 | INFO     | [Step 1/8] Validating input file...
                         2026-10-25 12:30:05 | INFO     | Input file found: incidents.csv
                         2026-10-25 12:30:06 | WARNING  | 3 records with unparseable dates excluded.
                         2026-10-25 12:30:08 | INFO     | PIPELINE COMPLETED SUCCESSFULLY

  import_log.txt    ← Records every file that was imported.
                       Each line shows: timestamp | filename | row count | status.
                       Example:
                         2026-10-25 12:30:05 | FILE: incidents.csv | ROWS: 1500 | STATUS: SUCCESS
                         2026-10-25 12:30:05 | FILE: bad_file.csv  | ROWS: 0   | STATUS: ERROR — missing column: threat_type

HOW TO USE THESE LOGS FOR DEBUGGING
─────────────────────────────────────
If the pipeline fails or produces unexpected results:
1. Open run_log.txt in any text editor (Notepad, VS Code, etc.)
2. Look for lines marked ERROR or WARNING.
3. The error message will tell you which file or step caused the problem.

The logs are APPENDED (not overwritten) each time the pipeline runs,
so you can see the history of all your pipeline runs.

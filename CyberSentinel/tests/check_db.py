import sqlite3
conn = sqlite3.connect("database/nctirap.db")
tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
print("DB Tables:")
for r in tables:
    count = conn.execute("SELECT COUNT(*) FROM " + r[0]).fetchone()[0]
    print(f"  {r[0]:<35} -> {count:,} rows")
conn.close()

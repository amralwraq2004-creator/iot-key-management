import sqlite3

conn = sqlite3.connect(r'database\iot_security.db')
cur = conn.cursor()

cur.execute("SELECT COUNT(*) FROM sensor_readings")
print(f"sensor_readings: {cur.fetchone()[0]} rows")

try:
    cur.execute("SELECT COUNT(*) FROM device_metrics")
    print(f"device_metrics:  {cur.fetchone()[0]} rows")
    print()
    print("=== Latest 3 device_metrics ===")
    cur.execute("SELECT * FROM device_metrics ORDER BY id DESC LIMIT 3")
    for row in cur.fetchall():
        print(f"  {row}")
except Exception as e:
    print(f"device_metrics error: {e}")

conn.close()
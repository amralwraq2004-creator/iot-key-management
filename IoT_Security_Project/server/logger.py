from datetime import datetime
from database import get_connection

def log_event(device_id, event_type, details=""):
    connection = get_connection()
    cursor = connection.cursor()

    timestamp = datetime.now().isoformat()

    cursor.execute("""
        INSERT INTO audit_logs (device_id, event_type, details, timestamp)
        VALUES (?, ?, ?, ?)
    """, (device_id, event_type, details, timestamp))

    connection.commit()
    connection.close()

def get_audit_logs():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT * FROM audit_logs ORDER BY id DESC
    """)

    logs = cursor.fetchall()
    connection.close()

    print("\n======================================")
    print("         SECURITY AUDIT LOGS")
    print("======================================")

    if not logs:
        print("[!] No audit logs found")
        return []

    for log in logs:
        print(f"[{log['timestamp']}] Device: {log['device_id']} | Event: {log['event_type']} | Details: {log['details']}")

    return logs

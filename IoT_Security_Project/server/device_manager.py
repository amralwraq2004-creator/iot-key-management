from datetime import datetime
from database import get_connection
from logger import log_event


def list_devices():
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT device_id, status, failed_attempts, created_at, updated_at,
               suspended_at, lockout_until
        FROM devices
        ORDER BY device_id
    """)
    rows = [dict(r) for r in cursor.fetchall()]
    connection.close()
    return rows


def get_device(device_id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,))
    row = cursor.fetchone()
    connection.close()
    return dict(row) if row else None


def reactivate_device(device_id):
    device = get_device(device_id)
    if not device:
        print(f"[!] Device not found: {device_id}")
        return False

    connection = get_connection()
    cursor = connection.cursor()
    now = datetime.now().isoformat()
    cursor.execute("""
        UPDATE devices
        SET status = 'ACTIVE',
            failed_attempts = 0,
            suspended_at = NULL,
            lockout_until = NULL,
            updated_at = ?
        WHERE device_id = ?
    """, (now, device_id))
    connection.commit()
    connection.close()

    log_event(device_id, "DEVICE_REACTIVATED", "Device reactivated by admin")
    print(f"[+] Device {device_id} reactivated successfully")
    print("[+] Status: ACTIVE")
    print("[+] Failed attempts reset to 0")
    return True


def suspend_device(device_id, reason="Suspended by admin"):
    device = get_device(device_id)
    if not device:
        print(f"[!] Device not found: {device_id}")
        return False

    connection = get_connection()
    cursor = connection.cursor()
    now = datetime.now().isoformat()
    cursor.execute("""
        UPDATE devices
        SET status = 'SUSPENDED',
            suspended_at = ?,
            updated_at = ?
        WHERE device_id = ?
    """, (now, now, device_id))
    connection.commit()
    connection.close()

    log_event(device_id, "DEVICE_SUSPENDED", reason)
    print(f"[+] Device {device_id} suspended")
    return True


def revoke_device(device_id):
    device = get_device(device_id)
    if not device:
        print(f"[!] Device not found: {device_id}")
        return False

    connection = get_connection()
    cursor = connection.cursor()
    now = datetime.now().isoformat()
    cursor.execute("""
        UPDATE devices
        SET status = 'REVOKED',
            updated_at = ?
        WHERE device_id = ?
    """, (now, device_id))
    connection.commit()
    connection.close()

    log_event(device_id, "DEVICE_REVOKED", "Device revoked by admin")
    print(f"[+] Device {device_id} revoked")
    return True

def reset_credential(device_id, new_credential):
    from authentication import hash_credential

    device = get_device(device_id)
    if not device:
        print(f"[!] Device not found: {device_id}")
        return False

    new_hash = hash_credential(new_credential)
    connection = get_connection()
    cursor = connection.cursor()
    now = datetime.now().isoformat()
    cursor.execute("""
        UPDATE devices
        SET credential_hash = ?,
            failed_attempts = 0,
            status = 'ACTIVE',
            suspended_at = NULL,
            lockout_until = NULL,
            updated_at = ?
        WHERE device_id = ?
    """, (new_hash, now, device_id))
    connection.commit()
    connection.close()

    log_event(device_id, "CREDENTIAL_RESET", "Credential reset by admin")
    print(f"[+] Credential for {device_id} has been reset")
    print("[+] Device status set to ACTIVE")
    print("[+] Failed attempts reset to 0")
    return True

def get_logs(device_id=None, limit=20):
    connection = get_connection()
    cursor = connection.cursor()
    if device_id:
        cursor.execute("""
            SELECT * FROM audit_logs
            WHERE device_id = ?
            ORDER BY id DESC
            LIMIT ?
        """, (device_id, limit))
    else:
        cursor.execute("""
            SELECT * FROM audit_logs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
    rows = [dict(r) for r in cursor.fetchall()]
    connection.close()
    return rows
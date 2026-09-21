import hashlib
from datetime import datetime, timedelta
from database import get_connection
from logger import log_event

MAX_FAILED_ATTEMPTS = 3
LOCKOUT_MINUTES = 5


def hash_credential(credential):
    return hashlib.sha256(credential.encode()).hexdigest()


def _lock_device(device_id, reason):
    connection = get_connection()
    cursor = connection.cursor()
    now = datetime.now()
    lockout_until = (now + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
    cursor.execute("""
        UPDATE devices
        SET status = 'LOCKED',
            lockout_until = ?,
            updated_at = ?
        WHERE device_id = ?
    """, (lockout_until, now.isoformat(), device_id))
    connection.commit()
    connection.close()

    log_event(device_id, "DEVICE_LOCKED",
              f"{reason} - locked for {LOCKOUT_MINUTES} minutes")


def _unlock_device(device_id):
    connection = get_connection()
    cursor = connection.cursor()
    now = datetime.now().isoformat()
    cursor.execute("""
        UPDATE devices
        SET status = 'ACTIVE',
            failed_attempts = 0,
            lockout_until = NULL,
            updated_at = ?
        WHERE device_id = ?
    """, (now, device_id))
    connection.commit()
    connection.close()

    log_event(device_id, "DEVICE_UNLOCKED",
              "Lockout expired, device reactivated automatically")


def _get_permissions(device_id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT permission FROM permissions WHERE device_id = ?",
                   (device_id,))
    perms = [row["permission"] for row in cursor.fetchall()]
    connection.close()
    return perms


def authenticate_device_ex(device_id, credential, issue_token=True):
    """
    Core authentication logic.
    Returns dict with session_token if successful.
    """
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT credential_hash, status, failed_attempts, lockout_until
        FROM devices WHERE device_id = ?
    """, (device_id,))
    device = cursor.fetchone()
    connection.close()

    if not device:
        log_event(device_id, "AUTH_FAILED", "Device not found")
        return {"success": False, "status": "NOT_FOUND",
                "reason": "Device not found",
                "remaining_seconds": None, "permissions": [],
                "session_token": None, "session_expires_at": None}

    # Temporary lockout check
    if device["status"] == "LOCKED" and device["lockout_until"]:
        lockout_until = datetime.fromisoformat(device["lockout_until"])
        now = datetime.now()
        if now < lockout_until:
            remaining = int((lockout_until - now).total_seconds())
            log_event(device_id, "AUTH_BLOCKED",
                      f"Attempted login while LOCKED ({remaining}s remaining)")
            return {"success": False, "status": "BLOCKED",
                    "reason": f"Device is LOCKED. Try again in {remaining}s",
                    "remaining_seconds": remaining, "permissions": [],
                    "session_token": None, "session_expires_at": None}
        else:
            _unlock_device(device_id)
            connection = get_connection()
            cursor = connection.cursor()
            cursor.execute("""
                SELECT credential_hash, status, failed_attempts, lockout_until
                FROM devices WHERE device_id = ?
            """, (device_id,))
            device = cursor.fetchone()
            connection.close()

    if device["status"] == "SUSPENDED":
        log_event(device_id, "AUTH_BLOCKED", "Attempted login while SUSPENDED")
        return {"success": False, "status": "BLOCKED",
                "reason": "Device is SUSPENDED",
                "remaining_seconds": None, "permissions": [],
                "session_token": None, "session_expires_at": None}

    if device["status"] != "ACTIVE":
        log_event(device_id, "AUTH_FAILED", "Device inactive")
        return {"success": False, "status": "DENIED",
                "reason": "Device inactive",
                "remaining_seconds": None, "permissions": [],
                "session_token": None, "session_expires_at": None}

    entered_hash = hash_credential(credential)

    if entered_hash == device["credential_hash"]:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute("""
            UPDATE devices
            SET failed_attempts = 0, updated_at = ?
            WHERE device_id = ?
        """, (datetime.now().isoformat(), device_id))
        connection.commit()
        connection.close()

        perms = _get_permissions(device_id)
        log_event(device_id, "AUTH_SUCCESS", "Authentication successful")

        session_token = None
        session_expires_at = None
        if issue_token:
            from session_manager import issue_session_token
            session = issue_session_token(device_id)
            session_token = session["token"]
            session_expires_at = session["expires_at"]

        return {"success": True, "status": "AUTHORIZED",
                "reason": "Authentication successful",
                "remaining_seconds": None, "permissions": perms,
                "session_token": session_token,
                "session_expires_at": session_expires_at}

    # Wrong credential
    connection = get_connection()
    cursor = connection.cursor()
    new_count = (device["failed_attempts"] or 0) + 1
    cursor.execute("""
        UPDATE devices
        SET failed_attempts = ?, updated_at = ?
        WHERE device_id = ?
    """, (new_count, datetime.now().isoformat(), device_id))
    connection.commit()
    connection.close()

    log_event(device_id, "AUTH_FAILED",
              f"Invalid credential (attempt {new_count}/{MAX_FAILED_ATTEMPTS})")

    if new_count >= MAX_FAILED_ATTEMPTS:
        _lock_device(device_id,
                     f"Locked due to {MAX_FAILED_ATTEMPTS} consecutive failed auth attempts")
        return {"success": False, "status": "BLOCKED",
                "reason": f"Device LOCKED for {LOCKOUT_MINUTES} minutes",
                "remaining_seconds": LOCKOUT_MINUTES * 60, "permissions": [],
                "session_token": None, "session_expires_at": None}

    return {"success": False, "status": "DENIED",
            "reason": f"Invalid credential (attempt {new_count}/{MAX_FAILED_ATTEMPTS})",
            "remaining_seconds": None, "permissions": [],
            "session_token": None, "session_expires_at": None}


def authenticate_device(device_id, credential):
    """Backwards-compatible wrapper: prints + returns bool."""
    result = authenticate_device_ex(device_id, credential, issue_token=False)
    status = result["status"]

    if status == "AUTHORIZED":
        print("[+] Authentication SUCCESS")
        print("[+] Device:", device_id)
    elif status == "BLOCKED":
        print(f"[ACCESS DENIED] {result['reason']}")
        print("[!] Authentication FAILED")
    elif status == "NOT_FOUND":
        print("[!] Device not found")
        print("[!] Authentication FAILED")
    else:
        print(f"[!] {result['reason']}")
        print("[!] Authentication FAILED")

    return result["success"]


def register_device(device_id, credential):
    """
    Register a new device.
    Creates:
      - Row in `devices` with credential_hash and a placeholder current_key.
      - Row in `key_history` (legacy).
      - Default permissions.
      - Row in `device_keys` (encrypted key, after device exists).
    """
    import secrets
    from key_manager import generate_device_key

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT device_id FROM devices WHERE device_id = ?", (device_id,))
    if cursor.fetchone():
        connection.close()
        print("[!] Device already exists")
        return False

    credential_hash = hash_credential(credential)
    timestamp = datetime.now().isoformat()

    # Placeholder key (will be superseded by device_keys entry below)
    placeholder_key = secrets.token_urlsafe(32)

    cursor.execute("""
        INSERT INTO devices
        (device_id, credential_hash, current_key, status, created_at,
         failed_attempts, updated_at)
        VALUES (?, ?, ?, ?, ?, 0, ?)
    """, (device_id, credential_hash, placeholder_key,
          "ACTIVE", timestamp, timestamp))

    cursor.execute("""
        INSERT INTO key_history (device_id, key_value, status, created_at)
        VALUES (?, ?, ?, ?)
    """, (device_id, placeholder_key, "ACTIVE", timestamp))

    default_permissions = ["READ_SENSOR", "PUBLISH_DATA"]
    for permission in default_permissions:
        cursor.execute(
            "INSERT INTO permissions (device_id, permission) VALUES (?, ?)",
            (device_id, permission)
        )

    connection.commit()
    connection.close()

    # Now that the device row exists, generate a real encrypted device key
    try:
        generate_device_key(device_id, "device_encryption", ttl_days=365)
    except Exception as e:
        print(f"[!] Warning: could not generate device_key: {e}")

    log_event(device_id, "DEVICE_REGISTERED",
              "Device successfully registered with default permissions")

    print("\n[+] Device registered successfully")
    print("[+] Device ID:", device_id)
    print("[+] Initial key generated")
    print("[+] Default permissions assigned")
    return True
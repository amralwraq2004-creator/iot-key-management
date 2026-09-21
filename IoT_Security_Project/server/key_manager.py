import secrets
from datetime import datetime, timedelta
from uuid import uuid4

from database import get_connection
from crypto_vault import encrypt, decrypt
from logger import log_event


DEFAULT_KEY_TTL_DAYS = 90
KEY_BYTES = 32  # 256-bit


def _now():
    return datetime.now().isoformat()


def _generate_key_value():
    """Generate a cryptographically secure random key (base64-ish)."""
    return secrets.token_urlsafe(KEY_BYTES)


def generate_device_key(device_id, purpose, ttl_days=DEFAULT_KEY_TTL_DAYS):
    """
    Generate a new key for a device and store it encrypted.
    Returns dict with key_id and plaintext key (only returned once).
    """
    key_id = str(uuid4())
    key_value = _generate_key_value()
    encrypted = encrypt(key_value)

    now = datetime.now()
    expires_at = (now + timedelta(days=ttl_days)).isoformat()

    connection = get_connection()
    cursor = connection.cursor()

    # Check device exists
    cursor.execute("SELECT device_id FROM devices WHERE device_id = ?", (device_id,))
    if not cursor.fetchone():
        connection.close()
        raise ValueError(f"Device not found: {device_id}")

    cursor.execute("""
        INSERT INTO device_keys
        (device_id, key_id, encrypted_key, purpose, is_active, created_at, expires_at)
        VALUES (?, ?, ?, ?, 1, ?, ?)
    """, (device_id, key_id, encrypted, purpose, now.isoformat(), expires_at))

    connection.commit()
    connection.close()

    log_event(device_id, "KEY_GENERATED",
              f"Key {key_id[:8]}... generated for purpose={purpose}, TTL={ttl_days}d")

    return {
        "key_id": key_id,
        "device_id": device_id,
        "purpose": purpose,
        "key_value": key_value,  # return plaintext ONCE to caller
        "created_at": now.isoformat(),
        "expires_at": expires_at,
    }


def get_active_key(device_id, purpose):
    """Return the plaintext active key for a device+purpose, or None."""
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT key_id, encrypted_key, created_at, expires_at
        FROM device_keys
        WHERE device_id = ? AND purpose = ? AND is_active = 1
          AND revoked_at IS NULL
        ORDER BY id DESC
        LIMIT 1
    """, (device_id, purpose))
    row = cursor.fetchone()
    connection.close()

    if not row:
        return None

    # Check expiry
    if row["expires_at"]:
        expires = datetime.fromisoformat(row["expires_at"])
        if datetime.now() > expires:
            revoke_key(row["key_id"], "expired")
            return None

    try:
        plaintext = decrypt(row["encrypted_key"])
    except Exception as e:
        print(f"[!] Decryption error for key {row['key_id']}: {e}")
        return None

    return {
        "key_id": row["key_id"],
        "key_value": plaintext,
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
    }


def rotate_key(device_id, purpose, ttl_days=DEFAULT_KEY_TTL_DAYS):
    """
    Rotate: deactivate old key, generate new one.
    Returns the new key dict.
    """
    now = _now()

    # Revoke old active key(s)
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        UPDATE device_keys
        SET is_active = 0, rotated_at = ?
        WHERE device_id = ? AND purpose = ? AND is_active = 1
    """, (now, device_id, purpose))
    connection.commit()
    connection.close()

    log_event(device_id, "KEY_ROTATED",
              f"Old key(s) for purpose={purpose} rotated out at {now}")

    # Generate new key
    return generate_device_key(device_id, purpose, ttl_days)


def revoke_key(key_id, reason="revoked_by_admin"):
    """Mark a specific key as revoked."""
    now = _now()
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT device_id, purpose FROM device_keys WHERE key_id = ?
    """, (key_id,))
    row = cursor.fetchone()

    if not row:
        connection.close()
        return False

    cursor.execute("""
        UPDATE device_keys
        SET is_active = 0, revoked_at = ?
        WHERE key_id = ?
    """, (now, key_id))
    connection.commit()
    connection.close()

    log_event(row["device_id"], "KEY_REVOKED",
              f"Key {key_id[:8]}... revoked: {reason}")
    return True


def revoke_all_keys(device_id, reason="revoked_all"):
    """Revoke all keys for a device."""
    now = _now()
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        UPDATE device_keys
        SET is_active = 0, revoked_at = ?
        WHERE device_id = ? AND is_active = 1
    """, (now, device_id))
    count = cursor.rowcount
    connection.commit()
    connection.close()

    if count:
        log_event(device_id, "ALL_KEYS_REVOKED",
                  f"Revoked {count} active key(s): {reason}")
    return count


def list_device_keys(device_id):
    """List all keys (metadata only, no plaintext)."""
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT key_id, purpose, is_active, created_at, expires_at,
               rotated_at, revoked_at
        FROM device_keys
        WHERE device_id = ?
        ORDER BY id DESC
    """, (device_id,))
    rows = [dict(r) for r in cursor.fetchall()]
    connection.close()
    return rows


def cleanup_expired_keys():
    """Mark expired keys as revoked."""
    now = _now()
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        UPDATE device_keys
        SET is_active = 0, revoked_at = ?
        WHERE is_active = 1
          AND expires_at IS NOT NULL
          AND expires_at < ?
    """, (now, now))
    count = cursor.rowcount
    connection.commit()
    connection.close()

    if count:
        print(f"[*] Cleaned up {count} expired keys")
    return count


def get_key_stats():
    """Return counts for dashboard."""
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) as c FROM device_keys")
    total = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) as c FROM device_keys WHERE is_active = 1")
    active = cursor.fetchone()["c"]

    cursor.execute("SELECT COUNT(*) as c FROM device_keys WHERE revoked_at IS NOT NULL")
    revoked = cursor.fetchone()["c"]

    connection.close()
    return {"total": total, "active": active, "revoked": revoked}
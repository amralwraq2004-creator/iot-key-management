import os
import json
import secrets
from datetime import datetime, timedelta

from database import get_connection
from crypto_vault import encrypt, decrypt, encrypt_dict, decrypt_dict
from key_manager import generate_device_key, rotate_key
from logger import log_event
from authentication import hash_credential


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERTS_DIR = os.path.join(BASE_DIR, "certs")

DEFAULT_TTL_MINUTES = 10
CODE_DIGITS = 6


def _now():
    return datetime.now().isoformat()


# ============================================================
#  Provisioning Code Generation
# ============================================================
def generate_provisioning_code(device_id, ttl_minutes=DEFAULT_TTL_MINUTES):
    """Generate a short numeric code for a device. Returns the code (only shown once)."""
    connection = get_connection()
    cursor = connection.cursor()

    # Check device exists
    cursor.execute("SELECT device_id FROM devices WHERE device_id = ?", (device_id,))
    if not cursor.fetchone():
        connection.close()
        raise ValueError(f"Device not found: {device_id}")

    # Invalidate any old unused codes
    cursor.execute("""
        UPDATE provisioning_tokens
        SET used_at = ?
        WHERE device_id = ? AND used_at IS NULL
    """, (_now(), device_id))

    # Generate 6-digit code
    code = "".join(str(secrets.randbelow(10)) for _ in range(CODE_DIGITS))

    now = datetime.now()
    expires_at = (now + timedelta(minutes=ttl_minutes)).isoformat()

    cursor.execute("""
        INSERT INTO provisioning_tokens
        (token, device_id, created_at, expires_at)
        VALUES (?, ?, ?, ?)
    """, (code, device_id, now.isoformat(), expires_at))

    connection.commit()
    connection.close()

    log_event(device_id, "PROVISIONING_CODE_CREATED",
              f"Code generated, expires in {ttl_minutes} min")

    return {
        "code": code,
        "device_id": device_id,
        "expires_at": expires_at,
    }


# ============================================================
#  Config Builders
# ============================================================
def _build_wifi_config():
    """WiFi config that will be sent to the device."""
    return {
        "ssid": os.environ.get("PROV_WIFI_SSID", "mosmos"),
        "password": os.environ.get("PROV_WIFI_PASSWORD", "93015647"),
    }


def _build_mqtt_config(device_id):
    """MQTT config + per-device credentials."""
    mqtt_username = f"dev_{device_id.lower().replace('-', '_')}"
    mqtt_password = secrets.token_urlsafe(24)

    return {
        "host": os.environ.get("PROV_MQTT_HOST", "192.168.8.114"),
        "port": int(os.environ.get("PROV_MQTT_PORT", "8883")),
        "client_id": f"{device_id}-client",
        "username": mqtt_username,
        "password": mqtt_password,
    }


def _load_ca_cert():
    """Load the CA certificate in PEM format."""
    ca_path = os.path.join(CERTS_DIR, "ca.crt")
    if not os.path.exists(ca_path):
        raise FileNotFoundError(f"CA cert not found: {ca_path}")
    with open(ca_path, "r", encoding="ascii") as f:
        return f.read()


# ============================================================
#  Database Sync Helpers
# ============================================================
def _sync_credential_hash(device_id, device_key_value):
    """
    Save credential_hash = hash(device_key) so the device can authenticate
    using its device_key (which the ESP32 stores in NVS).
    """
    h = hash_credential(device_key_value)

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        UPDATE devices
        SET credential_hash = ?,
            status = 'ACTIVE',
            failed_attempts = 0,
            lockout_until = NULL,
            updated_at = ?
        WHERE device_id = ?
    """, (h, _now(), device_id))
    connection.commit()
    connection.close()

    log_event(device_id, "CREDENTIAL_SYNCED",
              "credential_hash updated to match device_key during provisioning")


def _store_credentials(device_id, wifi_config, mqtt_config, ca_pem):
    """
    Store WiFi, MQTT credentials and CA cert in the credentials vault.
    These are encrypted with AES-256 before storage.
    """
    connection = get_connection()
    cursor = connection.cursor()
    now = _now()

    creds_to_store = [
        ("wifi_credentials", json.dumps(wifi_config)),
        ("mqtt_credentials", json.dumps(mqtt_config)),
        ("ca_certificate", ca_pem),
    ]

    for cred_type, value in creds_to_store:
        encrypted = encrypt(value)
        cursor.execute("""
            INSERT INTO credentials
            (device_id, credential_type, encrypted_value, algorithm,
             is_active, created_at)
            VALUES (?, ?, ?, 'AES-256-Fernet', 1, ?)
        """, (device_id, cred_type, encrypted, now))

    connection.commit()
    connection.close()

    log_event(device_id, "CREDENTIALS_STORED",
              f"Stored {len(creds_to_store)} credentials in vault (AES-256)")


# ============================================================
#  Payload Builder
# ============================================================
def build_provisioning_payload(device_id):
    """
    Build the full provisioning payload for a device.
    Also:
      - Rotates device encryption key
      - Syncs credential_hash in database
      - Stores credentials in vault
    """
    wifi = _build_wifi_config()
    mqtt = _build_mqtt_config(device_id)
    ca_pem = _load_ca_cert()

    # Rotate (revoke old, generate new) device encryption key
    device_key = rotate_key(device_id, "device_encryption", ttl_days=365)

    # Sync credential_hash with the new device_key
    _sync_credential_hash(device_id, device_key["key_value"])

    # Store credentials in vault (AES-256 encrypted)
    _store_credentials(device_id, wifi, mqtt, ca_pem)

    return {
        "device_id": device_id,
        "issued_at": _now(),
        "wifi": wifi,
        "mqtt": mqtt,
        "ca_certificate": ca_pem,
        "device_encryption_key": device_key["key_value"],
        "device_key_id": device_key["key_id"],
    }


# ============================================================
#  Code Validation & Consumption
# ============================================================
def validate_and_consume_code(code, device_mac=None):
    """
    Validate a provisioning code. If valid, return the provisioning payload.
    The code is marked used (single-use).
    """
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT token, device_id, created_at, expires_at, used_at
        FROM provisioning_tokens
        WHERE token = ?
    """, (code,))
    row = cursor.fetchone()

    # --- Check 1: Code exists? ---
    if not row:
        connection.close()
        log_event("UNKNOWN", "PROVISIONING_CODE_INVALID",
                  f"Invalid code attempted: {code[:2]}****")
        return {"success": False, "reason": "Invalid provisioning code"}

    # --- Check 2: Already used? ---
    if row["used_at"] is not None:
        connection.close()
        log_event(row["device_id"], "PROVISIONING_CODE_REUSED",
                  f"Attempted reuse of code {code[:2]}****")
        return {"success": False, "reason": "Code already used"}

    # --- Check 3: Expired? ---
    if datetime.fromisoformat(row["expires_at"]) < datetime.now():
        connection.close()
        log_event(row["device_id"], "PROVISIONING_CODE_EXPIRED",
                  f"Expired code attempted: {code[:2]}****")
        return {"success": False, "reason": "Code expired"}

    # --- All good: mark as used ---
    device_id = row["device_id"]

    cursor.execute("""
        UPDATE provisioning_tokens
        SET used_at = ?
        WHERE token = ?
    """, (_now(), code))
    connection.commit()
    connection.close()

    # --- Build payload (this also syncs credential_hash + stores credentials) ---
    payload = build_provisioning_payload(device_id)

    log_event(device_id, "PROVISIONING_COMPLETED",
              f"Payload delivered (MAC={device_mac or 'unknown'})")

    # --- Record provisioning event ---
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO provisioning_events (device_id, event_type, details, timestamp)
        VALUES (?, ?, ?, ?)
    """, (device_id, "PROVISIONING_SUCCESS",
          json.dumps({"mac": device_mac}), _now()))
    connection.commit()
    connection.close()

    return {
        "success": True,
        "device_id": device_id,
        "payload": payload,
    }


# ============================================================
#  Token Listing
# ============================================================
def list_provisioning_tokens(device_id=None, only_active=True):
    """List provisioning tokens (metadata only, masked)."""
    connection = get_connection()
    cursor = connection.cursor()

    query = """
        SELECT token, device_id, created_at, expires_at, used_at
        FROM provisioning_tokens
        WHERE 1=1
    """
    params = []

    if device_id:
        query += " AND device_id = ?"
        params.append(device_id)

    if only_active:
        query += " AND used_at IS NULL"
        query += " AND expires_at > ?"
        params.append(_now())

    query += " ORDER BY created_at DESC LIMIT 50"

    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    connection.close()

    # Mask tokens for safety
    for r in rows:
        r["token_masked"] = r["token"][:2] + "****"
        del r["token"]

    return rows


# ============================================================
#  CLI
# ============================================================
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python server/provisioning_manager.py generate <device_id>")
        print("  python server/provisioning_manager.py list [device_id]")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "generate":
        if len(sys.argv) < 3:
            print("Error: generate requires <device_id>")
            sys.exit(1)
        result = generate_provisioning_code(sys.argv[2])
        print(f"[+] Provisioning Code: {result['code']}")
        print(f"    Device: {result['device_id']}")
        print(f"    Expires: {result['expires_at']}")

    elif cmd == "list":
        device_id = sys.argv[2] if len(sys.argv) > 2 else None
        tokens = list_provisioning_tokens(device_id)
        print(json.dumps(tokens, indent=2, default=str))

    else:
        print(f"Unknown command: {cmd}")
        print("Use 'generate' or 'list'")
        sys.exit(1)
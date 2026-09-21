import secrets
from datetime import datetime, timedelta

from database import get_connection
from logger import log_event

SESSION_TTL_MINUTES = 30
TOKEN_BYTES = 32


def issue_session_token(device_id):
    token = secrets.token_urlsafe(TOKEN_BYTES)
    now = datetime.now()
    expires_at = now + timedelta(minutes=SESSION_TTL_MINUTES)

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO sessions (token, device_id, issued_at, expires_at, revoked)
        VALUES (?, ?, ?, ?, 0)
    """, (token, device_id, now.isoformat(), expires_at.isoformat()))
    connection.commit()
    connection.close()

    log_event(device_id, "SESSION_ISSUED", f"Session issued, TTL {SESSION_TTL_MINUTES}m")
    return {
        "token": token,
        "issued_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
    }


def validate_session_token(token, device_id=None):
    if not token:
        return None

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT token, device_id, issued_at, expires_at, revoked
        FROM sessions WHERE token = ?
    """, (token,))
    row = cursor.fetchone()
    connection.close()

    if not row:
        return None

    if row["revoked"]:
        return None

    if datetime.fromisoformat(row["expires_at"]) < datetime.now():
        return None

    if device_id and row["device_id"] != device_id:
        return None

    return dict(row)


def revoke_session_token(token):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("UPDATE sessions SET revoked = 1 WHERE token = ?", (token,))
    connection.commit()
    connection.close()


def revoke_all_sessions(device_id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("UPDATE sessions SET revoked = 1 WHERE device_id = ?", (device_id,))
    connection.commit()
    connection.close()
    log_event(device_id, "SESSIONS_REVOKED", "All active sessions revoked")


def cleanup_expired_sessions():
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("""
        DELETE FROM sessions
        WHERE expires_at < ? OR revoked = 1
    """, (datetime.now().isoformat(),))
    connection.commit()
    deleted = cursor.rowcount
    connection.close()
    return deleted
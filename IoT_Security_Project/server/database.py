import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_PATH = os.path.join(BASE_DIR, "database", "iot_security.db")


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def _column_exists(cursor, table, column):
    cursor.execute(f"PRAGMA table_info({table})")
    return any(row["name"] == column for row in cursor.fetchall())


def _run_migrations(cursor):
    if not _column_exists(cursor, "devices", "failed_attempts"):
        cursor.execute("ALTER TABLE devices ADD COLUMN failed_attempts INTEGER DEFAULT 0")
    if not _column_exists(cursor, "devices", "suspended_at"):
        cursor.execute("ALTER TABLE devices ADD COLUMN suspended_at TEXT")
    if not _column_exists(cursor, "devices", "lockout_until"):
        cursor.execute("ALTER TABLE devices ADD COLUMN lockout_until TEXT")
    if not _column_exists(cursor, "devices", "updated_at"):
        cursor.execute("ALTER TABLE devices ADD COLUMN updated_at TEXT")


def initialize_database():
    connection = get_connection()
    cursor = connection.cursor()

    # ===== Existing: devices =====
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            credential_hash TEXT NOT NULL,
            current_key TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            suspended_at TEXT,
            lockout_until TEXT,
            updated_at TEXT
        )
    """)

    # ===== Existing: key_history =====
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS key_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            key_value TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(device_id)
        )
    """)

    # ===== Existing: permissions =====
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            permission TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(device_id)
        )
    """)

    # ===== Existing: audit_logs =====
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT,
            timestamp TEXT NOT NULL
        )
    """)

    # ===== Existing: sessions =====
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked INTEGER DEFAULT 0,
            FOREIGN KEY (device_id) REFERENCES devices(device_id)
        )
    """)

    # ===== Existing: sensor_readings =====
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sensor_readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            temperature REAL,
            humidity REAL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(device_id)
        )
    """)

    # ===== New: Credentials Vault (encrypted) =====
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            credential_type TEXT NOT NULL,
            encrypted_value BLOB NOT NULL,
            algorithm TEXT NOT NULL DEFAULT 'AES-256-Fernet',
            is_active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            rotated_at TEXT,
            expires_at TEXT,
            revoked_at TEXT,
            revoked_reason TEXT,
            FOREIGN KEY (device_id) REFERENCES devices(device_id)
        )
    """)

    # ===== New: Device Keys (encrypted) =====
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            key_id TEXT NOT NULL UNIQUE,
            encrypted_key BLOB NOT NULL,
            purpose TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            rotated_at TEXT,
            expires_at TEXT,
            revoked_at TEXT,
            FOREIGN KEY (device_id) REFERENCES devices(device_id)
        )
    """)

    # ===== New: Provisioning Tokens (temporary) =====
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS provisioning_tokens (
            token TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            provisioning_data TEXT,
            FOREIGN KEY (device_id) REFERENCES devices(device_id)
        )
    """)

    # ===== New: Provisioning Events (audit) =====
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS provisioning_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(device_id)
        )
    """)

    _run_migrations(cursor)

    connection.commit()
    connection.close()


if __name__ == "__main__":
    initialize_database()
    print(f"[+] Database initialized at {DATABASE_PATH}")

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = [row["name"] for row in cursor.fetchall()]
    connection.close()

    print("[+] Tables:")
    for t in tables:
        print(f"    - {t}")
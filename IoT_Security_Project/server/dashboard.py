import os
from functools import wraps
from datetime import datetime, timedelta

from flask import (Flask, render_template, request, jsonify,
                   redirect, url_for, session, flash)

from database import get_connection, initialize_database
from device_manager import (list_devices, get_device, reactivate_device,
                            suspend_device, revoke_device,
                            reset_credential, get_logs)
from session_manager import (revoke_all_sessions, revoke_session_token,
                             cleanup_expired_sessions)
from key_manager import (get_key_stats, list_device_keys, generate_device_key,
                         rotate_key, revoke_key)


app = Flask(__name__)
app.secret_key = os.environ.get("DASHBOARD_SECRET", "change-me-in-production")

ADMIN_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "admin123")


# ============================================================
# Auth
# ============================================================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password", "")
        if password == ADMIN_PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("index"))
        flash("كلمة المرور خاطئة", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ============================================================
# Pages
# ============================================================
@app.route("/")
@login_required
def index():
    return render_template("overview.html", active="overview")


@app.route("/devices")
@login_required
def devices_page():
    return render_template("devices.html", active="devices")


@app.route("/keys")
@login_required
def keys_page():
    return render_template("keys.html", active="keys")


@app.route("/credentials")
@login_required
def credentials_page():
    return render_template("credentials.html", active="credentials")


@app.route("/provisioning")
@login_required
def provisioning_page():
    return render_template("provisioning.html", active="provisioning")


@app.route("/sessions")
@login_required
def sessions_page():
    return render_template("sessions.html", active="sessions")


@app.route("/logs")
@login_required
def logs_page():
    return render_template("logs.html", active="logs")


@app.route("/sensors")
@login_required
def sensors_page():
    return render_template("sensors.html", active="sensors")


@app.route("/health")
@login_required
def health_page():
    return render_template("health.html", active="health")


@app.route("/settings")
@login_required
def settings_page():
    return render_template("settings.html", active="settings")


# ============================================================
# API: Summary
# ============================================================
@app.route("/api/summary")
@login_required
def api_summary():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) as c FROM devices")
    total = cur.fetchone()["c"]

    cur.execute("SELECT status, COUNT(*) as c FROM devices GROUP BY status")
    by_status = {row["status"]: row["c"] for row in cur.fetchall()}

    cur.execute("""
        SELECT COUNT(*) as c FROM audit_logs
        WHERE event_type IN ('AUTH_FAILED', 'AUTH_BLOCKED', 'DEVICE_LOCKED',
                             'DEVICE_SUSPENDED', 'DEVICE_REVOKED')
        AND timestamp >= datetime('now', '-1 hour')
    """)
    alerts_1h = cur.fetchone()["c"]

    conn.close()

    try:
        key_stats = get_key_stats()
        active_keys = key_stats.get("active", 0)
    except Exception:
        active_keys = 0

    return jsonify({
        "total_devices": total,
        "active": by_status.get("ACTIVE", 0),
        "locked": by_status.get("LOCKED", 0),
        "suspended": by_status.get("SUSPENDED", 0),
        "revoked": by_status.get("REVOKED", 0),
        "alerts_1h": alerts_1h,
        "active_keys": active_keys,
    })


# ============================================================
# API: Devices
# ============================================================
@app.route("/api/devices")
@login_required
def api_devices():
    return jsonify(list_devices())


@app.route("/api/devices/<device_id>")
@login_required
def api_device_detail(device_id):
    dev = get_device(device_id)
    if not dev:
        return jsonify({"error": "not found"}), 404
    dev_safe = {k: v for k, v in dev.items() if k != "credential_hash"}
    return jsonify(dev_safe)


@app.route("/api/devices/<device_id>/delete", methods=["POST"])
@login_required
def api_device_delete(device_id):
    """
    حذف جهاز من قاعدة البيانات.
    يُرسل أمر clear_nvs للجهاز قبل الحذف (إن كان متصلًا).
    """
    import json
    import time
    import ssl as ssl_module
    import paho.mqtt.client as mqtt
    from logger import log_event

    conn = get_connection()
    cur = conn.cursor()

    # التحقق من وجود الجهاز
    cur.execute("SELECT device_id, status FROM devices WHERE device_id = ?", (device_id,))
    device_row = cur.fetchone()
    if not device_row:
        conn.close()
        return jsonify({"success": False, "error": "Device not found"}), 404

    remote_command_sent = False

    # === 1. أرسل أمر clear_nvs للجهاز عبر MQTT ===
    try:
        certs_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "certs"
        )
        ca_cert = os.path.join(certs_dir, "ca.crt")

        if os.path.exists(ca_cert):
            context = ssl_module.SSLContext(ssl_module.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl_module.CERT_NONE
            context.minimum_version = ssl_module.TLSVersion.TLSv1_2

            mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
            mqtt_client.tls_set_context(context)
            mqtt_client.connect("localhost", 8883, 5)
            mqtt_client.loop_start()

            time.sleep(0.5)

            topic = f"iot/devices/{device_id}/command"
            payload = json.dumps({
                "command": "clear_nvs",
                "reason": "device_deleted_by_admin"
            })
            mqtt_client.publish(topic, payload)
            time.sleep(0.5)

            mqtt_client.loop_stop()
            mqtt_client.disconnect()
            remote_command_sent = True
            print(f"[+] Clear NVS command sent to {device_id}")
    except Exception as e:
        print(f"[!] Could not send remote command: {e}")

    # === 2. سجّل العملية ===
    try:
        log_event(device_id, "DEVICE_DELETED",
                  f"Device deleted by admin (remote clear_nvs: {remote_command_sent})")
    except Exception:
        pass

    # === 3. احذف من الجداول ===
    deleted_counts = {}

    tables = [
        "sensor_readings",
        "device_metrics",
        "provisioning_events",
        "provisioning_tokens",
        "credentials",
        "sessions",
        "device_keys",
        "key_history",
        "permissions",
    ]

    for table in tables:
        try:
            cur.execute(f"DELETE FROM {table} WHERE device_id = ?", (device_id,))
            deleted_counts[table] = cur.rowcount
        except Exception as e:
            print(f"[!] Failed to delete from {table}: {e}")
            deleted_counts[table] = 0

    cur.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
    deleted_counts["devices"] = cur.rowcount

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "device_id": device_id,
        "deleted": deleted_counts,
        "remote_command_sent": remote_command_sent,
        "message": "Device deleted" + (
            " and clear_nvs sent to device" if remote_command_sent
            else " (device was not connected)"
        )
    })


@app.route("/api/register", methods=["POST"])
@login_required
def api_register():
    from authentication import register_device
    data = request.get_json() or {}
    device_id = data.get("device_id", "").strip()
    credential = data.get("credential", "").strip()

    if not device_id or not credential:
        return jsonify({"success": False, "error": "device_id and credential required"}), 400

    try:
        ok = register_device(device_id, credential)
        return jsonify({"success": bool(ok)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================
# API: Logs
# ============================================================
@app.route("/api/logs")
@login_required
def api_logs():
    device_id = request.args.get("device_id") or None
    limit = int(request.args.get("limit", 100))
    event_type = request.args.get("event_type") or None

    conn = get_connection()
    cur = conn.cursor()

    if device_id and event_type:
        cur.execute("""SELECT * FROM audit_logs WHERE device_id = ? AND event_type = ?
                       ORDER BY id DESC LIMIT ?""", (device_id, event_type, limit))
    elif device_id:
        cur.execute("""SELECT * FROM audit_logs WHERE device_id = ?
                       ORDER BY id DESC LIMIT ?""", (device_id, limit))
    elif event_type:
        cur.execute("""SELECT * FROM audit_logs WHERE event_type = ?
                       ORDER BY id DESC LIMIT ?""", (event_type, limit))
    else:
        cur.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))

    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/logs/event-types")
@login_required
def api_log_event_types():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT event_type FROM audit_logs ORDER BY event_type")
    rows = [r["event_type"] for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


# ============================================================
# API: Readings
# ============================================================
@app.route("/api/readings")
@login_required
def api_readings():
    device_id = request.args.get("device_id")
    limit = int(request.args.get("limit", 100))

    if not device_id:
        return jsonify({"error": "device_id required"}), 400

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT temperature, humidity, timestamp
        FROM sensor_readings
        WHERE device_id = ?
        ORDER BY id DESC
        LIMIT ?
    """, (device_id, limit))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    rows.reverse()
    return jsonify(rows)


@app.route("/api/readings/latest")
@login_required
def api_readings_latest():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT device_id, temperature, humidity, timestamp
        FROM sensor_readings
        ORDER BY id DESC
        LIMIT 50
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


# ============================================================
# API: Actions
# ============================================================
@app.route("/api/action", methods=["POST"])
@login_required
def api_action():
    data = request.get_json() or {}
    action = data.get("action")
    device_id = data.get("device_id")
    new_password = data.get("new_password")

    if not action or not device_id:
        return jsonify({"error": "action and device_id required"}), 400

    try:
        if action == "reactivate":
            ok = reactivate_device(device_id)
        elif action == "suspend":
            ok = suspend_device(device_id, "Suspended by admin via dashboard")
        elif action == "revoke":
            revoke_all_sessions(device_id)
            ok = revoke_device(device_id)
        elif action == "reset-credential":
            if not new_password:
                return jsonify({"error": "new_password required"}), 400
            ok = reset_credential(device_id, new_password)
        else:
            return jsonify({"error": f"unknown action: {action}"}), 400

        return jsonify({"success": bool(ok)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# API: Keys
# ============================================================
@app.route("/api/keys")
@login_required
def api_keys_all():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT key_id, device_id, purpose, is_active, created_at,
               expires_at, rotated_at, revoked_at
        FROM device_keys
        ORDER BY id DESC
        LIMIT 200
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/keys/<device_id>")
@login_required
def api_keys_device(device_id):
    try:
        return jsonify(list_device_keys(device_id))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/keys/stats")
@login_required
def api_keys_stats():
    try:
        return jsonify(get_key_stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/keys/generate", methods=["POST"])
@login_required
def api_keys_generate():
    data = request.get_json() or {}
    device_id = data.get("device_id")
    purpose = data.get("purpose", "device_encryption")

    if not device_id:
        return jsonify({"error": "device_id required"}), 400

    try:
        result = generate_device_key(device_id, purpose)
        return jsonify({"success": True, "key_id": result["key_id"],
                        "expires_at": result["expires_at"]})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/keys/rotate", methods=["POST"])
@login_required
def api_keys_rotate():
    data = request.get_json() or {}
    device_id = data.get("device_id")
    purpose = data.get("purpose", "device_encryption")

    if not device_id:
        return jsonify({"error": "device_id required"}), 400

    try:
        result = rotate_key(device_id, purpose)
        return jsonify({"success": True, "key_id": result["key_id"],
                        "expires_at": result["expires_at"]})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/keys/revoke", methods=["POST"])
@login_required
def api_keys_revoke():
    data = request.get_json() or {}
    key_id = data.get("key_id")
    reason = data.get("reason", "revoked_by_admin")

    if not key_id:
        return jsonify({"error": "key_id required"}), 400

    try:
        ok = revoke_key(key_id, reason)
        return jsonify({"success": bool(ok)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================
# API: Credentials (with Reveal feature)
# ============================================================
@app.route("/api/credentials")
@login_required
def api_credentials_all():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, device_id, credential_type, algorithm, is_active,
               created_at, rotated_at, expires_at, revoked_at
        FROM credentials
        ORDER BY id DESC
        LIMIT 200
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/credentials/<device_id>")
@login_required
def api_credentials_device(device_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, device_id, credential_type, algorithm, is_active,
               created_at, rotated_at, expires_at, revoked_at
        FROM credentials
        WHERE device_id = ?
        ORDER BY id DESC
    """, (device_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/credentials/<int:cred_id>/reveal", methods=["POST"])
@login_required
def api_credentials_reveal(cred_id):
    """Decrypt and return the secret value. Logs the reveal operation."""
    from crypto_vault import decrypt
    from logger import log_event

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, device_id, credential_type, encrypted_value
        FROM credentials
        WHERE id = ?
    """, (cred_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"success": False, "error": "not found"}), 404

    # Log the reveal operation
    try:
        log_event(row["device_id"], "CREDENTIAL_REVEALED",
                  f"Secret #{cred_id} ({row['credential_type']}) decrypted by admin")
    except Exception:
        pass

    try:
        encrypted_bytes = row["encrypted_value"]
        if isinstance(encrypted_bytes, str):
            encrypted_bytes = encrypted_bytes.encode("utf-8")

        plaintext = decrypt(encrypted_bytes)
        return jsonify({
            "success": True,
            "id": cred_id,
            "device_id": row["device_id"],
            "credential_type": row["credential_type"],
            "value": plaintext,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================
# API: Provisioning
# ============================================================
@app.route("/api/provisioning/tokens")
@login_required
def api_prov_tokens():
    from provisioning_manager import list_provisioning_tokens
    return jsonify(list_provisioning_tokens(only_active=False))


@app.route("/api/provisioning/generate", methods=["POST"])
@login_required
def api_prov_generate():
    from provisioning_manager import generate_provisioning_code
    data = request.get_json() or {}
    device_id = data.get("device_id")

    if not device_id:
        return jsonify({"error": "device_id required"}), 400

    try:
        result = generate_provisioning_code(device_id)
        return jsonify({"success": True, "code": result["code"],
                        "expires_at": result["expires_at"],
                        "device_id": result["device_id"]})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/provisioning/events")
@login_required
def api_prov_events():
    limit = int(request.args.get("limit", 50))
    device_id = request.args.get("device_id")

    conn = get_connection()
    cur = conn.cursor()
    if device_id:
        cur.execute("""SELECT * FROM provisioning_events WHERE device_id = ?
                       ORDER BY id DESC LIMIT ?""", (device_id, limit))
    else:
        cur.execute("SELECT * FROM provisioning_events ORDER BY id DESC LIMIT ?",
                    (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


# ============================================================
# API: Sessions
# ============================================================
@app.route("/api/sessions")
@login_required
def api_sessions():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT token, device_id, issued_at, expires_at, revoked
        FROM sessions
        ORDER BY issued_at DESC
        LIMIT 100
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    for r in rows:
        r["token_masked"] = r["token"][:12] + "..."
        del r["token"]
    return jsonify(rows)


@app.route("/api/sessions/revoke", methods=["POST"])
@login_required
def api_sessions_revoke():
    data = request.get_json() or {}
    token = data.get("token")
    device_id = data.get("device_id")

    try:
        if token:
            revoke_session_token(token)
        elif device_id:
            revoke_all_sessions(device_id)
        else:
            return jsonify({"error": "token or device_id required"}), 400
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/sessions/cleanup", methods=["POST"])
@login_required
def api_sessions_cleanup():
    try:
        deleted = cleanup_expired_sessions()
        return jsonify({"success": True, "deleted": deleted})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================
# API: Health
# ============================================================
@app.route("/api/health")
@login_required
def api_health():
    import socket
    result = {
        "time": datetime.now().isoformat(),
        "services": [],
    }

    # Check Mosquitto 8883
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(("127.0.0.1", 8883))
        s.close()
        result["services"].append({"name": "Mosquitto MQTT TLS", "port": 8883, "status": "UP"})
    except Exception:
        result["services"].append({"name": "Mosquitto MQTT TLS", "port": 8883, "status": "DOWN"})

    # Check Provisioning API 5443
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(("127.0.0.1", 5443))
        s.close()
        result["services"].append({"name": "Provisioning API", "port": 5443, "status": "UP"})
    except Exception:
        result["services"].append({"name": "Provisioning API", "port": 5443, "status": "DOWN"})

    # Database stats
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as c FROM devices")
    result["devices"] = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM device_keys WHERE is_active = 1")
    result["active_keys"] = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM sessions WHERE revoked = 0 AND expires_at > ?",
                (datetime.now().isoformat(),))
    result["active_sessions"] = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM audit_logs")
    result["total_logs"] = cur.fetchone()["c"]
    conn.close()

    result["db_path"] = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                     "database", "iot_security.db")
    try:
        result["db_size_kb"] = round(os.path.getsize(result["db_path"]) / 1024, 1)
    except Exception:
        result["db_size_kb"] = 0

    return jsonify(result)


# ============================================================
# Main
# ============================================================
def main():
    initialize_database()
    print("[*] Dashboard starting on http://localhost:5000")
    print(f"[*] Admin password: {ADMIN_PASSWORD}")
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
import os
from functools import wraps

from flask import (Flask, render_template, request, jsonify,
                   redirect, url_for, session, flash)

from database import get_connection, initialize_database
from device_manager import (list_devices, get_device, reactivate_device,
                            suspend_device, revoke_device,
                            reset_credential, get_logs)
from session_manager import revoke_all_sessions


app = Flask(__name__)
app.secret_key = os.environ.get("DASHBOARD_SECRET", "change-me-in-production")

ADMIN_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "admin123")


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


@app.route("/")
@login_required
def index():
    return render_template("index.html")


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

    return jsonify({
        "total_devices": total,
        "active": by_status.get("ACTIVE", 0),
        "locked": by_status.get("LOCKED", 0),
        "suspended": by_status.get("SUSPENDED", 0),
        "revoked": by_status.get("REVOKED", 0),
        "alerts_1h": alerts_1h,
    })


@app.route("/api/devices")
@login_required
def api_devices():
    return jsonify(list_devices())


@app.route("/api/logs")
@login_required
def api_logs():
    device_id = request.args.get("device_id") or None
    limit = int(request.args.get("limit", 50))
    return jsonify(get_logs(device_id, limit))


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


def main():
    initialize_database()
    print("[*] Dashboard starting on http://localhost:5000")
    print(f"[*] Admin password: {ADMIN_PASSWORD}")
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()

import os
import json
from datetime import datetime
from flask import Flask, request, jsonify

from database import initialize_database, get_connection
from provisioning_manager import (
    generate_provisioning_code,
    validate_and_consume_code,
    list_provisioning_tokens,
)

app = Flask(__name__)

ADMIN_PASSWORD = os.environ.get("PROVISIONING_ADMIN_PASSWORD", "admin123")

CERTS_DIR = r"C:\Users\Elite\Desktop\IoT_Security_Project\certs"
CERT_FILE = os.path.join(CERTS_DIR, "server.crt")
KEY_FILE = os.path.join(CERTS_DIR, "server.key")

PORT = int(os.environ.get("PROVISIONING_PORT", "5443"))


def check_admin(req):
    key = req.headers.get("X-Admin-Key", "")
    return key == ADMIN_PASSWORD


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "provisioning-api",
        "time": datetime.now().isoformat(),
    })


@app.route("/api/provision/request", methods=["POST"])
def provision_request():
    """Admin generates a provisioning code for a device."""
    if not check_admin(request):
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json() or {}
    device_id = data.get("device_id")

    if not device_id:
        return jsonify({"error": "device_id required"}), 400

    try:
        result = generate_provisioning_code(device_id)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404


@app.route("/api/provision/consume", methods=["POST"])
def provision_consume():
    """Device sends code + MAC, receives secrets payload."""
    data = request.get_json() or {}
    code = data.get("code")
    device_mac = data.get("device_mac", "unknown")
    firmware_version = data.get("firmware_version", "unknown")

    if not code:
        return jsonify({"error": "code required"}), 400

    result = validate_and_consume_code(code, device_mac=device_mac)

    if not result.get("success"):
        return jsonify(result), 403

    result["firmware_version"] = firmware_version
    return jsonify(result)


@app.route("/api/provision/status/<device_id>", methods=["GET"])
def provision_status(device_id):
    """Get provisioning history for a device."""
    if not check_admin(request):
        return jsonify({"error": "unauthorized"}), 401

    tokens = list_provisioning_tokens(device_id, only_active=False)

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT event_type, details, timestamp
        FROM provisioning_events
        WHERE device_id = ?
        ORDER BY id DESC
        LIMIT 20
    """, (device_id,))
    events = [dict(r) for r in cur.fetchall()]
    conn.close()

    return jsonify({
        "device_id": device_id,
        "tokens": tokens,
        "events": events,
    })


@app.route("/api/provision/tokens", methods=["GET"])
def provision_tokens():
    """List all active provisioning tokens (admin only)."""
    if not check_admin(request):
        return jsonify({"error": "unauthorized"}), 401

    return jsonify(list_provisioning_tokens())


def main():
    initialize_database()

    print("=" * 55)
    print("  Provisioning API Server")
    print("=" * 55)
    print(f"[*] HTTPS port: {PORT}")
    print(f"[*] Admin password: {ADMIN_PASSWORD}")
    print(f"[*] Cert: {CERT_FILE}")
    print(f"[*] Key:  {KEY_FILE}")
    print()

    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        print("[!] ERROR: Certificate or key not found!")
        return

    app.run(
        host="0.0.0.0",
        port=PORT,
        ssl_context=(CERT_FILE, KEY_FILE),
        debug=False,
    )


if __name__ == "__main__":
    main()

import json
import os
import ssl
from datetime import datetime

import paho.mqtt.client as mqtt

from database import initialize_database, get_connection
from authentication import authenticate_device_ex
from session_manager import validate_session_token, cleanup_expired_sessions

USE_TLS = os.environ.get("MQTT_USE_TLS", "1") == "1"
BROKER_HOST = "localhost"
BROKER_PORT = 8883 if USE_TLS else 1883
CA_CERT = r"C:\Users\Elite\Desktop\IoT_Security_Project\certs\ca.crt"

AUTH_REQUEST_TOPIC = "iot/auth/request"
AUTH_RESPONSE_PREFIX = "iot/auth/response"
SENSOR_DATA_TOPIC = "iot/sensors/+/data"


def build_ssl_context(ca_path):
    with open(ca_path, "rb") as f:
        ca_data = f.read().decode("ascii")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=ca_data)
    return context


def on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        mode = "TLS" if USE_TLS else "plain"
        print(f"[+] Connected to MQTT broker at {BROKER_HOST}:{BROKER_PORT} ({mode})")
        client.subscribe(AUTH_REQUEST_TOPIC)
        client.subscribe(SENSOR_DATA_TOPIC)
        print(f"[+] Subscribed to: {AUTH_REQUEST_TOPIC}")
        print(f"[+] Subscribed to: {SENSOR_DATA_TOPIC}")
    else:
        print(f"[!] Failed to connect, reason code: {reason_code}")


def handle_auth_request(client, payload):
    device_id = payload.get("device_id")
    credential = payload.get("credential")

    if not device_id or not credential:
        print("[!] Auth request missing device_id or credential")
        return

    print(f"[>] Auth request from: {device_id}")
    result = authenticate_device_ex(device_id, credential)
    result["device_id"] = device_id

    topic = f"{AUTH_RESPONSE_PREFIX}/{device_id}"
    client.publish(topic, json.dumps(result))
    print(f"[<] Auth response published to {topic}")
    print(json.dumps(result, indent=2))


def _store_reading(device_id, data):
    """Store sensor reading + device metrics in the database."""
    if not isinstance(data, dict):
        return

    temperature = data.get("temperature")
    humidity = data.get("humidity")
    chip_temp = data.get("chip_temp")
    rssi = data.get("rssi")
    free_heap = data.get("free_heap")
    min_free_heap = data.get("min_free_heap")
    uptime = data.get("uptime")

    now = datetime.now().isoformat()

    try:
        conn = get_connection()
        cur = conn.cursor()

        if temperature is not None or humidity is not None:
            cur.execute("""
                INSERT INTO sensor_readings (device_id, temperature, humidity, timestamp)
                VALUES (?, ?, ?, ?)
            """, (device_id, temperature, humidity, now))

        if chip_temp is not None or rssi is not None:
            cur.execute("""
                INSERT INTO device_metrics
                (device_id, chip_temp, rssi, free_heap, min_free_heap, uptime, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (device_id, chip_temp, rssi, free_heap, min_free_heap, uptime, now))

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] Failed to store reading: {e}")

def handle_sensor_data(client, topic, payload):
    # topic format: iot/sensors/{device_id}/data
    parts = topic.split("/")
    if len(parts) != 4:
        print(f"[!] Invalid topic format: {topic}")
        return
    topic_device_id = parts[2]

    token = payload.get("session_token")
    data = payload.get("data")
    claimed_device_id = payload.get("device_id")

    reject_topic = f"iot/sensors/{topic_device_id}/reject"

    if not token:
        print(f"[!] Sensor data without token from {topic_device_id}")
        client.publish(
            reject_topic,
            json.dumps({"status": "REJECTED", "reason": "Missing session_token"})
        )
        return

    session = validate_session_token(token, device_id=topic_device_id)
    if not session:
        print(f"[!] Invalid or expired session token from {topic_device_id}")
        client.publish(
            reject_topic,
            json.dumps({"status": "REJECTED",
                        "reason": "Invalid or expired session token"})
        )
        return

    if claimed_device_id and claimed_device_id != topic_device_id:
        print(f"[!] Device ID mismatch: topic={topic_device_id}, payload={claimed_device_id}")
        client.publish(
            reject_topic,
            json.dumps({"status": "REJECTED", "reason": "Device ID mismatch"})
        )
        return

    # Store reading for dashboard
    _store_reading(topic_device_id, data)

    print(f"[+] Sensor data accepted from {topic_device_id}: {data}")
    client.publish(
        f"iot/sensors/{topic_device_id}/ack",
        json.dumps({"status": "OK", "device_id": topic_device_id})
    )


def on_message(client, userdata, msg):
    print(f"\n[>] Message received on {msg.topic}")
    try:
        payload = json.loads(msg.payload.decode())
    except Exception as e:
        print(f"[!] Invalid JSON payload: {e}")
        return

    if msg.topic == AUTH_REQUEST_TOPIC:
        handle_auth_request(client, payload)
    elif msg.topic.startswith("iot/sensors/") and msg.topic.endswith("/data"):
        handle_sensor_data(client, msg.topic, payload)
    else:
        print(f"[!] Unhandled topic: {msg.topic}")


def main():
    initialize_database()
    deleted = cleanup_expired_sessions()
    if deleted:
        print(f"[*] Cleaned up {deleted} expired/revoked sessions")

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message

    if USE_TLS:
        print(f"[*] Loading CA from: {CA_CERT}")
        client.tls_set_context(build_ssl_context(CA_CERT))
        print("[*] TLS context configured")

    print(f"[*] Connecting to MQTT broker at {BROKER_HOST}:{BROKER_PORT}...")
    client.connect(BROKER_HOST, BROKER_PORT, 60)

    print("[*] MQTT Service started. Press Ctrl+C to stop.\n")
    client.loop_forever()


if __name__ == "__main__":
    main()
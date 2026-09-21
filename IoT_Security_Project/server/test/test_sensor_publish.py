import json
import os
import ssl
import time
import paho.mqtt.client as mqtt

BROKER_HOST = "localhost"
BROKER_PORT = 8883
CA_CERT = r"C:\Users\Elite\Desktop\IoT_Security_Project\certs\ca.crt"

AUTH_REQUEST_TOPIC = "iot/auth/request"
AUTH_RESPONSE_PREFIX = "iot/auth/response"
SENSOR_DATA_TOPIC = "iot/sensors/{device_id}/data"

DEVICE_ID = "ESP32-01"
CREDENTIAL = "MyNewPass123"

inbox = {}
connected_event = False
session_token = None


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
    global connected_event
    if reason_code == 0:
        client.subscribe(f"{AUTH_RESPONSE_PREFIX}/{DEVICE_ID}")
        client.subscribe(f"iot/sensors/{DEVICE_ID}/ack")
        client.subscribe(f"iot/sensors/{DEVICE_ID}/reject")
        connected_event = True
    else:
        print(f"[!] Connect failed: {reason_code}")


def on_message(client, userdata, msg):
    try:
        inbox[msg.topic] = json.loads(msg.payload.decode())
    except Exception as e:
        inbox[msg.topic] = {"error": str(e)}


def wait_for(topic, timeout=5):
    start = time.time()
    while topic not in inbox and time.time() - start < timeout:
        time.sleep(0.1)
    return inbox.pop(topic, None)


def main():
    global connected_event, session_token

    print("==========================================")
    print("  SENSOR PUBLISH TEST (with session token)")
    print("==========================================")

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    client.tls_set_context(build_ssl_context(CA_CERT))

    client.connect(BROKER_HOST, BROKER_PORT, 60)
    client.loop_start()

    start = time.time()
    while not connected_event and time.time() - start < 5:
        time.sleep(0.1)

    if not connected_event:
        print("[!] Could not connect")
        return

    print("[+] Connected over TLS")

    # Step 1: Authenticate
    print("\n--- Step 1: Authenticate ---")
    client.publish(AUTH_REQUEST_TOPIC, json.dumps({
        "device_id": DEVICE_ID,
        "credential": CREDENTIAL,
    }))
    auth_resp = wait_for(f"{AUTH_RESPONSE_PREFIX}/{DEVICE_ID}")
    print(json.dumps(auth_resp, indent=2))

    if not auth_resp or not auth_resp.get("success"):
        print("[!] Authentication failed, aborting")
        client.loop_stop()
        return

    session_token = auth_resp.get("session_token")
    print(f"[+] Got session token: {session_token[:20]}...")

    # Step 2: Publish sensor data WITHOUT token (should be rejected)
    print("\n--- Step 2: Publish WITHOUT token ---")
    topic = SENSOR_DATA_TOPIC.format(device_id=DEVICE_ID)
    client.publish(topic, json.dumps({
        "device_id": DEVICE_ID,
        "data": {"temperature": 25.5, "humidity": 60},
    }))
    reject = wait_for(f"iot/sensors/{DEVICE_ID}/reject")
    print(f"Reject response: {reject}")

    # Step 3: Publish sensor data WITH valid token
    print("\n--- Step 3: Publish WITH valid token ---")
    client.publish(topic, json.dumps({
        "device_id": DEVICE_ID,
        "session_token": session_token,
        "data": {"temperature": 25.5, "humidity": 60},
    }))
    ack = wait_for(f"iot/sensors/{DEVICE_ID}/ack")
    print(f"Ack response: {ack}")

    # Step 4: Try to publish with wrong token
    print("\n--- Step 4: Publish WITH invalid token ---")
    client.publish(topic, json.dumps({
        "device_id": DEVICE_ID,
        "session_token": "fake-token-abcdef",
        "data": {"temperature": 99.9},
    }))
    reject2 = wait_for(f"iot/sensors/{DEVICE_ID}/reject")
    print(f"Reject response: {reject2}")

    print("\n==========================================")
    print("  TEST COMPLETED")
    print("==========================================")

    client.loop_stop()
    client.disconnect()


if __name__ == "__main__":
    main()
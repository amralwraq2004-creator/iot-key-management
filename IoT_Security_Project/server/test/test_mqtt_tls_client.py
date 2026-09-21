import json
import os
import ssl
import time
import paho.mqtt.client as mqtt

BROKER_HOST = "localhost"
BROKER_PORT = 8883
CA_CERT = r"C:\Users\Elite\Desktop\IoT_Security_Project\certs\ca.crt"

REQUEST_TOPIC = "iot/auth/request"
RESPONSE_TOPIC_PREFIX = "iot/auth/response"

DEVICE_ID = "ESP32-01"
CREDENTIAL = "MyNewPass123"


response_queue = []
connected_event = False


def build_ssl_context(ca_path):
    print(f"[*] CA path: {ca_path}")
    print(f"[*] Exists: {os.path.exists(ca_path)}")

    if not os.path.exists(ca_path):
        raise FileNotFoundError(f"CA not found at {ca_path}")

    with open(ca_path, "rb") as f:
        raw = f.read()
    print(f"[*] CA size: {len(raw)} bytes")
    print(f"[*] First 30 bytes: {raw[:30]!r}")

    ca_data = raw.decode("ascii")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=ca_data)
    return context


def on_connect(client, userdata, flags, reason_code, properties=None):
    global connected_event
    if reason_code == 0:
        topic = f"{RESPONSE_TOPIC_PREFIX}/{DEVICE_ID}"
        client.subscribe(topic)
        connected_event = True
    else:
        print(f"[!] Connect failed: {reason_code}")


def on_message(client, userdata, msg):
    try:
        response_queue.append(json.loads(msg.payload.decode()))
    except Exception as e:
        response_queue.append({"error": str(e)})


def wait_for_response(timeout=5):
    start = time.time()
    while not response_queue and time.time() - start < timeout:
        time.sleep(0.1)
    return response_queue.pop(0) if response_queue else None


def main():
    global connected_event

    print("==========================================")
    print("  MQTT AUTH TEST OVER TLS")
    print("==========================================")

    context = build_ssl_context(CA_CERT)
    print("[+] SSL context ready")

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message

    client.tls_set_context(context)

    client.connect(BROKER_HOST, BROKER_PORT, 60)
    client.loop_start()

    start = time.time()
    while not connected_event and time.time() - start < 5:
        time.sleep(0.1)

    if not connected_event:
        print("[!] Could not connect over TLS")
        client.loop_stop()
        return

    print("[+] TLS connection established")
    print(f"[+] Subscribed to {RESPONSE_TOPIC_PREFIX}/{DEVICE_ID}")

    request = {"device_id": DEVICE_ID, "credential": CREDENTIAL}
    client.publish(REQUEST_TOPIC, json.dumps(request))
    print(f"[>] Request sent: {request}")

    response = wait_for_response()
    print("\n[<] Response:")
    print(json.dumps(response, indent=2))

    client.loop_stop()
    client.disconnect()


if __name__ == "__main__":
    main()
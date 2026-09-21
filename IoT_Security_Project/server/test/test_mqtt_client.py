import json
import time
import paho.mqtt.client as mqtt

BROKER_HOST = "localhost"
BROKER_PORT = 1883
REQUEST_TOPIC = "iot/auth/request"
RESPONSE_TOPIC_PREFIX = "iot/auth/response"

DEVICE_ID = "ESP32-01"
WRONG_CREDENTIAL = "WrongPass"
CORRECT_CREDENTIAL = "MyNewPass123"


response_queue = []
connected_event = False


def on_connect(client, userdata, flags, reason_code, properties=None):
    global connected_event
    if reason_code == 0:
        topic = f"{RESPONSE_TOPIC_PREFIX}/{DEVICE_ID}"
        client.subscribe(topic)
        connected_event = True


def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
        response_queue.append(data)
    except Exception as e:
        response_queue.append({"error": str(e)})


def wait_for_response(timeout=5):
    start = time.time()
    while not response_queue and time.time() - start < timeout:
        time.sleep(0.1)
    if response_queue:
        return response_queue.pop(0)
    return None


def send_request(client, credential):
    request = {"device_id": DEVICE_ID, "credential": credential}
    client.publish(REQUEST_TOPIC, json.dumps(request))
    return wait_for_response()


def print_result(label, credential, response):
    print(f"\n===== {label} =====")
    print(f"Credential: {credential}")
    if response is None:
        print("[!] No response received")
        return
    print(f"Status: {response.get('status')}")
    print(f"Success: {response.get('success')}")
    print(f"Reason: {response.get('reason')}")
    if response.get("remaining_seconds") is not None:
        print(f"Remaining: {response.get('remaining_seconds')}s")
    if response.get("permissions"):
        print(f"Permissions: {response.get('permissions')}")


def main():
    global connected_event

    print("==========================================")
    print("  MQTT AUTH SECURITY TEST")
    print("==========================================")

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(BROKER_HOST, BROKER_PORT, 60)
    client.loop_start()

    # Wait until connected + subscribed
    start = time.time()
    while not connected_event and time.time() - start < 5:
        time.sleep(0.1)

    if not connected_event:
        print("[!] Could not connect to broker")
        return

    print(f"[+] Connected and subscribed to {RESPONSE_TOPIC_PREFIX}/{DEVICE_ID}")

    # 3 wrong attempts
    for i in range(1, 4):
        r = send_request(client, WRONG_CREDENTIAL)
        print_result(f"WRONG ATTEMPT {i}", WRONG_CREDENTIAL, r)

    # Correct credential during lockout
    r = send_request(client, CORRECT_CREDENTIAL)
    print_result("CORRECT CREDENTIAL DURING LOCKOUT", CORRECT_CREDENTIAL, r)

    print("\n==========================================")
    print("  TEST COMPLETED")
    print("==========================================")

    client.loop_stop()
    client.disconnect()


if __name__ == "__main__":
    main()
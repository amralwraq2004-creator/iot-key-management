import serial
import time
import sys

PORT = "COM19"       # غير الرقم إذا اختلف
BAUD = 115200

# ⚠️ غير هذا إلى الكود الجديد الذي ولدته
CODE = "680114"

print(f"[*] Opening {PORT} at {BAUD}...")
try:
    ser = serial.Serial(PORT, BAUD, timeout=1)
except Exception as e:
    print(f"[!] Cannot open {PORT}: {e}")
    print("[!] تأكد أن Serial Monitor مغلق في Arduino IDE")
    sys.exit(1)

time.sleep(1)

print("[*] Resetting ESP32 (sending RTS pulse)...")
ser.setDTR(False)
ser.setRTS(True)
time.sleep(0.1)
ser.setRTS(False)
time.sleep(0.5)

print("[*] Reading ESP32 output for 3 seconds...")
start = time.time()
while time.time() - start < 3:
    if ser.in_waiting:
        try:
            line = ser.readline().decode('utf-8', errors='ignore')
            print(line, end='')
        except:
            pass

print(f"\n[*] Sending code: {CODE}")
ser.write((CODE + "\n").encode())
ser.flush()
time.sleep(1)

print("[*] Reading ESP32 output for 30 seconds...")
start = time.time()
while time.time() - start < 30:
    if ser.in_waiting:
        try:
            line = ser.readline().decode('utf-8', errors='ignore')
            print(line, end='')
        except:
            pass

ser.close()
print("\n[*] Done.")
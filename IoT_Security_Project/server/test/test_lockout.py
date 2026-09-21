import sys
sys.path.insert(0, "server")

from database import initialize_database
from authentication import authenticate_device

initialize_database()

DEVICE_ID = "ESP32-01"
WRONG = "WrongPass999"
CORRECT = "MyNewPass123"

print("\n========== SIMULATING BRUTE-FORCE ==========")
for i in range(1, 4):
    print(f"\n--- Attempt {i} (Wrong Pass) ---")
    authenticate_device(DEVICE_ID, WRONG)

print("\n========== LEGITIMATE LOGIN DURING LOCKOUT ==========")
authenticate_device(DEVICE_ID, CORRECT)
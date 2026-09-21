from database import initialize_database
from authentication import (
    register_device,
    authenticate_device
)
from authorization import authorize_action
from logger import get_audit_logs

print("======================================")
print("       IoT SECURITY SYSTEM")
print("    BRUTE-FORCE MITIGATION VERSION")
print("======================================")

# DATABASE INITIALIZATION
initialize_database()
print("\n[+] Database ready")

device_id = "ESP32-01"
credential = "IoT@12345"

# 1. REGISTER DEVICE
register_device(device_id, credential)

# 2. VALID AUTHENTICATION
print("\n========== VALID AUTHENTICATION ==========")
authenticate_device(device_id, credential)

# 3. SIMULATE BRUTE-FORCE ATTACK (3 Wrong Attempts)
print("\n======================================")
print("     SIMULATING BRUTE-FORCE ATTACK")
print("======================================")

print("\n--- Attempt 1 (Wrong Pass) ---")
authenticate_device(device_id, "Wrong_1")

print("\n--- Attempt 2 (Wrong Pass) ---")
authenticate_device(device_id, "Wrong_2")

print("\n--- Attempt 3 (Wrong Pass - Triggers Ban) ---")
authenticate_device(device_id, "Wrong_3")

# 4. TRY VALID AUTHENTICATION AFTER SUSPENSION
print("\n========== LEGITIMATE LOGIN AFTER BAN ==========")
authenticate_device(device_id, credential)

# 5. PRINT AUDIT LOGS
get_audit_logs()

print("\n======================================")
print("       TEST COMPLETED")
print("======================================")
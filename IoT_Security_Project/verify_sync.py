import sys
sys.path.insert(0, 'server')

from database import get_connection
from authentication import hash_credential

DEVICE_ID = 'ESP32-02'
EXPECTED_KEY = '3zbd2vk7z07IO9yCZkGbDYyvTGxwH9-esPCzFqfsu38'

c = get_connection()
row = c.execute(
    "SELECT device_id, credential_hash, status, failed_attempts FROM devices WHERE device_id = ?",
    (DEVICE_ID,)
).fetchone()
c.close()

if not row:
    print(f"[!] Device {DEVICE_ID} not found")
    sys.exit(1)

stored_hash = row['credential_hash']
expected_hash = hash_credential(EXPECTED_KEY)

print(f"Device ID:     {row['device_id']}")
print(f"Status:        {row['status']}")
print(f"Failed:        {row['failed_attempts']}")
print(f"Stored hash:   {stored_hash[:40]}...")
print(f"Expected hash: {expected_hash[:40]}...")
print(f"Match:         {stored_hash == expected_hash}")
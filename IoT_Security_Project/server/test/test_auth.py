import sys
sys.path.insert(0, "server")

from database import initialize_database
from authentication import authenticate_device

initialize_database()

DEVICE_ID = "ESP32-01"
# ضع هنا كلمة المرور الصحيحة التي استخدمتها عند التسجيل
CREDENTIAL = "MyNewPass123"
print("========== TEST AUTHENTICATION ==========")
result = authenticate_device(DEVICE_ID, CREDENTIAL)
print("Result:", "SUCCESS" if result else "FAILED")
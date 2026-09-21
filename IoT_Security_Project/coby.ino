// ============================================================
//  IoT Key Management System — ESP32 Client
//  Version: v2.1 (Built-in Sensors Edition)
//  Features: NVS + Provisioning + NTP + Full TLS + Real Sensors
// ============================================================

// ============ 1. الترويسات (Includes) ============

#include <WiFi.h>                 // مكتبة ESP32 للاتصال بـ WiFi
#include <WiFiClientSecure.h>     // مكتبة الاتصال الآمن (TLS/SSL)
#include <PubSubClient.h>         // مكتبة MQTT للتواصل مع Mosquitto
#include <ArduinoJson.h>          // مكتبة تحليل وبناء JSON
#include <Preferences.h>          // مكتبة NVS (تخزين دائم في Flash)
#include <HTTPClient.h>           // مكتبة إرسال طلبات HTTP/HTTPS
#include <time.h>                 // مكتبة الوقت (NTP)

// ============================================================
//  2. إعدادات Bootstrap (للتزويد الأولي فقط)
// ============================================================

// اسم شبكة WiFi التي سيستخدمها ESP32 للتزويد الأولي
const char* BOOTSTRAP_WIFI_SSID     = "mosmos";

// كلمة مرور شبكة WiFi
const char* BOOTSTRAP_WIFI_PASSWORD = "93015647";

// عنوان IP لخادم التزويد (Provisioning API)
const char* PROVISIONING_HOST = "192.168.8.114";

// منفذ خادم التزويد (HTTPS)
const int   PROVISIONING_PORT = 5443;

// ============================================================
//  3. شهادة CA (للتحقق من هوية الخادم)
// ============================================================

// شهادة CA موقّعة ذاتيًا للتحقق من HTTPS
// هذا ليس سرًا - الشهادة عامة (المفتاح الخاص محفوظ على الخادم)
const char* BOOTSTRAP_CA_CERT =
"-----BEGIN CERTIFICATE-----\n"
"MIIDrTCCApWgAwIBAgIUenULjUEOSUlgIHzx1kgruGFR4FowDQYJKoZIhvcNAQEL\n"
"BQAwZjELMAkGA1UEBhMCWUUxDjAMBgNVBAgMBVNhbmFhMQ4wDAYDVQQHDAVTYW5h\n"
"YTEdMBsGA1UECgwUSW9UIFNlY3VyaXR5IFByb2plY3QxGDAWBgNVBAMMD0lvVC1T\n"
"ZWN1cml0eS1DQTAeFw0yNjA5MTgwMTMwMzVaFw0zNjA5MTUwMTMwMzVaMGYxCzAJ\n"
"BgNVBAYTAllFMQ4wDAYDVQQIDAVTYW5hYTEOMAwGA1UEBwwFU2FuYWExHTAbBgNV\n"
"BAoMFElvVCBTZWN1cml0eSBQcm9qZWN0MRgwFgYDVQQDDA9Jb1QtU2VjdXJpdHkt\n"
"Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCxx0hiUuo/Y8o6rOsp\n"
"YGEj/BNJsFtChm9+4qZwV3YprIUMmT+nsCJFbZUzETrV+hOUIrY3ckKcbpmIU7/N\n"
"leJlaDO+j+QfgznaRZ/TAPYWG6BB+1iiy0SHhlrBrTG9IJOGM1K3F8l6AohMNBv7\n"
"2lB/s3oxy0f1E+WctqIFats6+eolLO2SV//Q0beN7TbRrx2M2HO2YKpvWKk0EAkZ\n"
"CuWFigBnJLDeB9g19dYEdt+gclPY3pMMBeFpyQLwuz9U+jkCYjYXAOiDY2IjXvC9\n"
"qB5UtF39xWydUu+LGsz5pS76FC01HwHaOcZp2YZrp1AcsmQDDYScxGcnH19JSy7e\n"
"qIAzAgMBAAGjUzBRMB0GA1UdDgQWBBRrUxkC4FwtpiqzVRswY2n9zefdCzAfBgNV\n"
"HSMEGDAWgBRrUxkC4FwtpiqzVRswY2n9zefdCzAPBgNVHRMBAf8EBTADAQH/MA0G\n"
"CSqGSIb3DQEBCwUAA4IBAQCFCLvMir95PYPeBlbHDBY405KXgCz1b5sO/uUPXuWS\n"
"hBsR9AqqQU7U3Py9P202p4pHcCgAZwESIQaYuZSqE5vzfavQrkpSXqeBsmZtQpge\n"
"5YY/RzG5/q46ml8JI0KoUklTr57ZG/QbDQ/WN32E6B6EzIDivAEfBR9LbMFKoqB/\n"
"7g6M8A/9Vo/JNtgCJM5xTmdMfGBFlW3tgr3fvSDseeUJxN87Sxv6BieOwBvQjN7h\n"
"pKPYyIW2EP3HfjbCr2lcDnHorlmAmKE5F1Oxc7pc20s1MhGuI7Nxl31e54OS5iDa\n"
"PS/Dfd56rqgwkgM+vHMvHwk36m0jXmgeMnNc1Geb+Aa6\n"
"-----END CERTIFICATE-----\n";

// ============================================================
//  4. NVS + المتغيرات العامة
// ============================================================

Preferences prefs;                          // كائن NVS للقراءة والكتابة

const char* NVS_NAMESPACE = "iot-config";   // اسم مساحة NVS

// هيكل بيانات لحفظ كل ما يستلمه ESP32 من Provisioning
struct DeviceConfig {
  String wifi_ssid;        // اسم شبكة WiFi
  String wifi_password;    // كلمة مرور WiFi
  String mqtt_host;        // عنوان خادم MQTT (IP)
  int    mqtt_port;        // منفذ MQTT (8883)
  String mqtt_username;    // اسم مستخدم MQTT
  String mqtt_password;    // كلمة مرور MQTT
  String mqtt_client_id;   // معرّف عميل MQTT
  String device_id;        // معرّف الجهاز (ESP32-01)
  String ca_cert;          // شهادة CA من الخادم
  String device_key;       // مفتاح الجهاز الفريد (للمصادقة)
  String device_key_id;    // معرّف المفتاح (للتدوير)
};

DeviceConfig config;                        // نسخة فعلية من الهيكل

WiFiClientSecure secureClient;              // عميل TLS
PubSubClient     mqttClient(secureClient);  // عميل MQTT يستخدم TLS

String sessionToken = "";                   // رمز الجلسة من المصادقة
unsigned long tokenIssuedAt    = 0;         // وقت إصدار الرمز
const unsigned long TOKEN_LIFETIME_MS   = 25UL * 60UL * 1000UL;  // 25 دقيقة

unsigned long lastPublish      = 0;         // وقت آخر إرسال بيانات
const unsigned long PUBLISH_INTERVAL_MS = 10000;  // 10 ثوانٍ

unsigned long lastReconnectAttempt = 0;     // وقت آخر محاولة إعادة اتصال MQTT

// أسماء مواضيع MQTT (تُبنى في setup)
String topic_auth_request;      // iot/auth/request
String topic_auth_response;     // iot/auth/response/ESP32-01
String topic_sensor_data;       // iot/sensors/ESP32-01/data
String topic_sensor_ack;        // iot/sensors/ESP32-01/ack
String topic_sensor_reject;     // iot/sensors/ESP32-01/reject

// ============================================================
//  5. إعلانات مسبقة للدوال
// ============================================================

void runProvisioningMode();                 // وضع التزويد
bool provisionDevice(const String& code);   // تنفيذ التزويد
String readCodeFromSerial();                // قراءة الكود من Serial
bool loadConfigFromNVS();                   // تحميل الإعدادات من NVS
void saveConfigToNVS(JsonObject& payload);  // حفظ الإعدادات في NVS
void clearNVS();                            // مسح NVS
void connectWiFi();                         // الاتصال بـ WiFi
void connectMQTT();                         // الاتصال بـ MQTT
void publishAuthRequest();                  // إرسال طلب المصادقة
void publishSensorData();                   // إرسال بيانات المستشعرات
void onMqttMessage(char* topic, byte* payload, unsigned int length);  // معالجة الرسائل
void syncTime();                            // مزامنة الوقت

// ============================================================
//  6. مزامنة الوقت عبر NTP
// ============================================================

void syncTime() {
  // طباعة رسالة بدء المزامنة
  Serial.println("[*] Syncing time via NTP...");
  
  // طلب الوقت من خوادم NTP (UTC بدون offset)
  configTime(0, 0, "pool.ntp.org", "time.nist.gov", "time.google.com");

  // قراءة الوقت الحالي (ثواني من 1970)
  time_t now = time(nullptr);
  int retries = 0;
  
  // الانتظار حتى ضبط الوقت أو انتهاء 60 محاولة (30 ثانية)
  while (now < 100000 && retries < 60) {
    delay(500);                             // انتظار نصف ثانية
    Serial.print(".");                      // طباعة نقطة كتقدم
    now = time(nullptr);                    // إعادة قراءة الوقت
    retries++;                              // زيادة العداد
  }
  Serial.println();                         // سطر جديد

  // إذا فشلت المزامنة (الوقت أقل من 1970-01-02)
  if (now < 100000) {
    Serial.println("[!] NTP sync FAILED");  // طباعة تحذير
    return;                                 // الخروج من الدالة
  }

  // تحويل الوقت إلى هيكل tm
  struct tm timeinfo;
  gmtime_r(&now, &timeinfo);
  
  // طباعة الوقت المُزامن
  Serial.printf("[+] Time synced: %04d-%02d-%02d %02d:%02d:%02d UTC\n",
                timeinfo.tm_year + 1900,    // السنة (يبدأ من 1900)
                timeinfo.tm_mon + 1,        // الشهر (يبدأ من 0)
                timeinfo.tm_mday,           // اليوم
                timeinfo.tm_hour,           // الساعة
                timeinfo.tm_min,            // الدقيقة
                timeinfo.tm_sec);           // الثانية
}

// ============================================================
//  7. setup() - نقطة البداية
// ============================================================

void setup() {
  Serial.begin(115200);                     // تشغيل المنفذ التسلسلي
  delay(1000);                              // انتظار ثانية للاستقرار
  Serial.println();                         // سطر جديد
  Serial.println("==========================================");
  Serial.println("  IoT Key Management — ESP32 Client v2.1");
  Serial.println("  (Built-in Sensors Edition)");
  Serial.println("==========================================");

  // فتح مساحة NVS (false = قراءة وكتابة)
  prefs.begin(NVS_NAMESPACE, false);

  // قراءة حالة التزويد من NVS (القيمة الافتراضية: false)
  bool provisioned = prefs.getBool("provisioned", false);

  // إذا لم يكن مُزوَّدًا
  if (!provisioned) {
    Serial.println("[!] Device is NOT provisioned.");
    runProvisioningMode();                  // ادخل وضع التزويد
    return;                                 // لن يُنفَّذ بعدها
  }

  // طباعة حالة التحميل
  Serial.println("[+] Device is provisioned. Loading config from NVS...");
  
  // محاولة تحميل الإعدادات من NVS
  if (!loadConfigFromNVS()) {
    Serial.println("[!] Failed to load config from NVS.");
    clearNVS();                             // امسح NVS
    runProvisioningMode();                  // ادخل وضع التزويد
    return;                                 // لن يُنفَّذ بعدها
  }

  // طباعة الإعدادات المُحمّلة
  Serial.printf("[+] Device ID: %s\n", config.device_id.c_str());
  Serial.printf("[+] WiFi SSID (from NVS): %s\n", config.wifi_ssid.c_str());
  Serial.printf("[+] MQTT Host (from NVS): %s:%d\n", config.mqtt_host.c_str(), config.mqtt_port);

  // بناء أسماء المواضيع (Topics)
  topic_auth_request   = "iot/auth/request";                            // ثابت
  topic_auth_response  = "iot/auth/response/" + config.device_id;       // ديناميكي
  topic_sensor_data    = "iot/sensors/" + config.device_id + "/data";   // ديناميكي
  topic_sensor_ack     = "iot/sensors/" + config.device_id + "/ack";    // ديناميكي
  topic_sensor_reject  = "iot/sensors/" + config.device_id + "/reject"; // ديناميكي

  // الاتصال بـ WiFi
  connectWiFi();
  
  // مزامنة الوقت (ضروري للتحقق من الشهادات)
  syncTime();

  // MQTT TLS (setInsecure بسبب مشكلة IP-SAN في ESP32 core 3.3.11)
  secureClient.setInsecure();               // تعطيل التحقق من شهادة Mosquitto
  Serial.println("[!] MQTT: setInsecure() — see Known Issues");
  Serial.println("[!] Provisioning API still uses full CA verification");

  // إعداد عميل MQTT
  mqttClient.setServer(config.mqtt_host.c_str(), config.mqtt_port);  // عنوان الخادم
  mqttClient.setCallback(onMqttMessage);                             // دالة معالجة الرسائل
  mqttClient.setBufferSize(2048);                                    // حجم buffer 2KB

  // الاتصال بـ MQTT وإرسال طلب مصادقة
  connectMQTT();
  publishAuthRequest();
}

// ============================================================
//  8. loop() - التكرار اللانهائي
// ============================================================

void loop() {
  // إذا انقطع WiFi، أعد الاتصال وأعد مزامنة الوقت
  if (WiFi.status() != WL_CONNECTED) {
    connectWiFi();
    syncTime();
  }

  // إذا انقطع MQTT
  if (!mqttClient.connected()) {
    unsigned long now = millis();
    // لا تحاول إعادة الاتصال أكثر من مرة كل 5 ثوانٍ
    if (now - lastReconnectAttempt > 5000) {
      lastReconnectAttempt = now;
      connectMQTT();
    }
    return;                                 // اخرج من loop
  }

  // معالجة الرسائل الواردة (يجب استدعاؤها بانتظام)
  mqttClient.loop();

  unsigned long now = millis();             // الوقت الحالي

  // إذا اقترب انتهاء صلاحية الرمز (25 دقيقة) → جدّده
  if (sessionToken.length() > 0 && now - tokenIssuedAt > TOKEN_LIFETIME_MS) {
    Serial.println("[!] Token nearing expiry, re-authenticating...");
    sessionToken = "";
    publishAuthRequest();
  }

  // إذا مرت 10 ثوانٍ → أرسل بيانات المستشعرات
  if (sessionToken.length() > 0 && now - lastPublish > PUBLISH_INTERVAL_MS) {
    lastPublish = now;
    publishSensorData();
  }
}

// ============================================================
//  9. تحميل الإعدادات من NVS
// ============================================================

bool loadConfigFromNVS() {
  // قراءة كل حقل من NVS (القيمة الثانية = الافتراضية)
  config.wifi_ssid      = prefs.getString("wifi_ssid", "");
  config.wifi_password  = prefs.getString("wifi_pass", "");
  config.mqtt_host      = prefs.getString("mqtt_host", "");
  config.mqtt_port      = prefs.getInt("mqtt_port", 8883);       // 8883 افتراضيًا
  config.mqtt_username  = prefs.getString("mqtt_user", "");
  config.mqtt_password  = prefs.getString("mqtt_pass", "");
  config.mqtt_client_id = prefs.getString("mqtt_cid", "");
  config.device_id      = prefs.getString("device_id", "");
  config.ca_cert        = prefs.getString("ca_cert", "");
  config.device_key     = prefs.getString("dev_key", "");
  config.device_key_id  = prefs.getString("dev_key_id", "");

  // التحقق من أن الحقول الأساسية موجودة
  if (config.wifi_ssid.isEmpty() || config.mqtt_host.isEmpty() ||
      config.device_id.isEmpty() || config.ca_cert.isEmpty()) {
    return false;                           // البيانات تالفة
  }
  return true;                              // البيانات سليمة
}

// ============================================================
//  10. حفظ الإعدادات في NVS
// ============================================================

void saveConfigToNVS(JsonObject& payload) {
  // استخراج الكائنات الفرعية
  JsonObject wifi = payload["wifi"];
  JsonObject mqtt = payload["mqtt"];

  // حفظ بيانات WiFi
  prefs.putString("wifi_ssid", wifi["ssid"].as<String>());
  prefs.putString("wifi_pass", wifi["password"].as<String>());
  
  // حفظ بيانات MQTT
  prefs.putString("mqtt_host", mqtt["host"].as<String>());
  prefs.putInt("mqtt_port", mqtt["port"].as<int>());
  prefs.putString("mqtt_user", mqtt["username"].as<String>());
  prefs.putString("mqtt_pass", mqtt["password"].as<String>());
  prefs.putString("mqtt_cid",  mqtt["client_id"].as<String>());
  
  // حفظ بيانات الجهاز
  prefs.putString("device_id",   payload["device_id"].as<String>());
  prefs.putString("ca_cert",     payload["ca_certificate"].as<String>());
  prefs.putString("dev_key",     payload["device_encryption_key"].as<String>());
  prefs.putString("dev_key_id",  payload["device_key_id"].as<String>());
  
  // ضع علامة "مُزوَّد" حتى لا نُعيد التزويد في المرة القادمة
  prefs.putBool("provisioned", true);
  
  Serial.println("[+] Config saved to NVS.");
}

// ============================================================
//  11. مسح NVS
// ============================================================

void clearNVS() {
  prefs.clear();                            // حذف كل مفاتيح مساحة iot-config
  Serial.println("[!] NVS cleared.");
}

// ============================================================
//  12. قراءة كود التزويد من Serial
// ============================================================

String readCodeFromSerial() {
  Serial.println();
  Serial.println("========================================");
  Serial.println("  Enter 6-digit provisioning code:");
  Serial.println("========================================");

  String code = "";                         // الكود المُجمَّع
  unsigned long start = millis();           // وقت البدء
  const unsigned long timeout = 120000;     // 120 ثانية كحد أقصى

  // الحلقة الرئيسية
  while (millis() - start < timeout) {
    // إذا كانت هناك بيانات في Serial
    if (Serial.available()) {
      char c = Serial.read();               // اقرأ حرفًا
      
      // إذا كان Enter (سطر جديد أو CR)
      if (c == '\n' || c == '\r') {
        if (code.length() == 6) {           // إذا كان الطول 6
          Serial.println();
          return code;                      // أعد الكود
        } else if (code.length() > 0) {     // إذا كان هناك شيء لكن الطول خطأ
          Serial.println();
          Serial.println("[!] Invalid length. Try again:");
          code = "";                        // أعد التعيين
        }
      }
      // إذا كان رقمًا (0-9)
      else if (c >= '0' && c <= '9') {
        code += c;                          // أضف الرقم
        Serial.print(c);                    // اطبع للتأكيد
      }
      // الأحرف الأخرى تُتجاهل
    }
    delay(50);                              // صغير لتفريغ المعالج
  }

  // إذا انتهى الوقت
  Serial.println();
  Serial.println("[!] Timeout.");
  return "";                                // أعد سلسلة فارغة
}

// ============================================================
//  13. تنفيذ عملية التزويد
// ============================================================

bool provisionDevice(const String& code) {
  Serial.println();
  Serial.println("[*] Connecting to bootstrap WiFi...");
  
  // الاتصال بشبكة WiFi للـ bootstrap
  WiFi.mode(WIFI_STA);                      // وضع Client
  WiFi.begin(BOOTSTRAP_WIFI_SSID, BOOTSTRAP_WIFI_PASSWORD);

  int retries = 0;
  // الانتظار حتى الاتصال أو انتهاء 40 محاولة (20 ثانية)
  while (WiFi.status() != WL_CONNECTED && retries < 40) {
    delay(500);
    Serial.print(".");
    retries++;
  }
  Serial.println();

  // إذا فشل الاتصال
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("[!] Failed to connect to bootstrap WiFi.");
    return false;
  }

  // طباعة IP
  Serial.print("[+] Bootstrap WiFi connected. IP: ");
  Serial.println(WiFi.localIP());

  // مزامنة الوقت (حرج للتحقق من الشهادة)
  syncTime();

  // إنشاء عميل TLS للـ Provisioning
  WiFiClientSecure provClient;
  provClient.setCACert(BOOTSTRAP_CA_CERT);  // تفعيل التحقق الكامل من الشهادة
  Serial.println("[+] HTTPS: CA cert verification ENABLED");

  // تجهيز طلب HTTP
  HTTPClient http;
  String url = String("https://") + PROVISIONING_HOST + ":" +
               String(PROVISIONING_PORT) + "/api/provision/consume";

  Serial.println("[*] POST " + url);

  // بدء الاتصال
  if (!http.begin(provClient, url)) {
    Serial.println("[!] http.begin() failed");
    return false;
  }

  // تحديد نوع المحتوى
  http.addHeader("Content-Type", "application/json");

  // بناء جسم الطلب
  StaticJsonDocument<256> req;
  req["code"]             = code;                  // الكود المُدخل
  req["device_mac"]       = WiFi.macAddress();     // عنوان MAC
  req["firmware_version"] = "2.1.0-sensors";       // إصدار الـ firmware

  String body;
  serializeJson(req, body);                        // JSON → String

  Serial.println("[>] Request body:");
  Serial.println(body);

  // إرسال الطلب
  int httpCode = http.POST(body);
  Serial.printf("[<] HTTP code: %d\n", httpCode);

  // إذا لم يكن 200
  if (httpCode != 200) {
    String resp = http.getString();
    Serial.println("[!] Response body:");
    Serial.println(resp);
    http.end();                                    // أغلق الاتصال
    return false;
  }

  // قراءة الرد
  String response = http.getString();
  http.end();                                      // أغلق الاتصال

  Serial.println("[+] Response received. Parsing...");

  // تحليل JSON (8KB لأن الرد يحتوي شهادة CA)
  DynamicJsonDocument doc(8192);
  DeserializationError err = deserializeJson(doc, response);

  if (err) {
    Serial.printf("[!] JSON parse error: %s\n", err.c_str());
    return false;
  }

  // التحقق من النجاح
  if (!doc["success"].as<bool>()) {
    Serial.println("[!] Provisioning rejected:");
    Serial.println(doc["reason"].as<String>());
    return false;
  }

  // استخراج payload
  JsonObject payload = doc["payload"].as<JsonObject>();
  if (payload.isNull()) {
    Serial.println("[!] No payload in response");
    return false;
  }

  // حفظ في NVS
  saveConfigToNVS(payload);

  Serial.println();
  Serial.println("[+] Provisioning complete!");
  Serial.println("[*] Rebooting in 3 seconds...");
  delay(3000);                                     // انتظار 3 ثوانٍ
  ESP.restart();                                   // إعادة التشغيل
  return true;
}

// ============================================================
//  14. وضع التزويد
// ============================================================

void runProvisioningMode() {
  Serial.println();
  Serial.println("========================================");
  Serial.println("         PROVISIONING MODE");
  Serial.println("========================================");

  // اقرأ الكود من المستخدم
  String code = readCodeFromSerial();

  // إذا لم يكن 6 أرقام → أعد التشغيل
  if (code.length() != 6) {
    Serial.println("[!] No valid code. Rebooting in 5 seconds...");
    delay(5000);
    ESP.restart();
  }

  // حاول التزويد
  if (!provisionDevice(code)) {
    Serial.println("[!] Provisioning failed. Rebooting in 5 seconds...");
    delay(5000);
    ESP.restart();
  }
}

// ============================================================
//  15. الاتصال بـ WiFi (Normal Mode)
// ============================================================

void connectWiFi() {
  Serial.printf("[*] Connecting to WiFi: %s\n", config.wifi_ssid.c_str());
  WiFi.mode(WIFI_STA);                      // وضع Client
  WiFi.begin(config.wifi_ssid.c_str(), config.wifi_password.c_str());

  int retries = 0;
  // الانتظار حتى الاتصال أو 20 ثانية
  while (WiFi.status() != WL_CONNECTED && retries < 40) {
    delay(500);
    Serial.print(".");
    retries++;
  }
  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {
    Serial.print("[+] WiFi connected. IP: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("[!] WiFi connection failed. Retrying in 5s...");
    delay(5000);
  }
}

// ============================================================
//  16. الاتصال بـ MQTT
// ============================================================

void connectMQTT() {
  Serial.printf("[*] Connecting to MQTT over TLS: %s:%d\n",
                config.mqtt_host.c_str(), config.mqtt_port);

  // استخدام client_id من NVS، أو إنشاء واحد عشوائي
  String clientId = config.mqtt_client_id;
  if (clientId.isEmpty()) {
    clientId = config.device_id + "-" + String(random(0xffff), HEX);
  }

  bool ok;
  // إذا كان هناك username/password → استخدم المصادقة
  if (config.mqtt_username.length() > 0) {
    ok = mqttClient.connect(clientId.c_str(),
                            config.mqtt_username.c_str(),
                            config.mqtt_password.c_str());
  } else {
    // اتصال بدون مصادقة MQTT
    ok = mqttClient.connect(clientId.c_str());
  }

  if (ok) {
    Serial.println("[+] MQTT connected over TLS");
    // الاشتراك في 3 مواضيع
    mqttClient.subscribe(topic_auth_response.c_str());  // ردود المصادقة
    mqttClient.subscribe(topic_sensor_ack.c_str());      // تأكيدات
    mqttClient.subscribe(topic_sensor_reject.c_str());   // رفض
    Serial.printf("[+] Subscribed to: %s\n", topic_auth_response.c_str());
  } else {
    Serial.printf("[!] MQTT connect failed, rc=%d\n", mqttClient.state());
  }
}

// ============================================================
//  17. إرسال طلب المصادقة
// ============================================================

void publishAuthRequest() {
  StaticJsonDocument<256> doc;
  doc["device_id"]  = config.device_id;     // معرّف الجهاز
  doc["credential"] = config.device_key;    // المفتاح (سيكون credential)

  char buffer[256];
  serializeJson(doc, buffer);               // JSON → String

  Serial.println("[>] Publishing auth request...");
  mqttClient.publish(topic_auth_request.c_str(), buffer);
}

// ============================================================
//  18. إرسال بيانات المستشعرات
// ============================================================

void publishSensorData() {
  // === مستشعر حقيقي: حرارة الشريحة الداخلية ===
  float chip_temp = temperatureRead();      // دالة ESP32 داخلية

  // حرارة البيئة = حرارة الشريحة - offset + noise
  // Offset عادة 10-15°C (الشريحة تسخّن نفسها)
  float offset = 12.0 + (random(-20, 20) / 10.0);   // 10.0 إلى 14.0
  float temp_noise = (random(-50, 50) / 100.0);     // ±0.5°C
  float temperature = chip_temp - offset + temp_noise;

  // === رطوبة افتراضية: محاكاة واقعية ===
  unsigned long uptime_sec = millis() / 1000;
  float day_cycle = sin((uptime_sec % 86400) / 86400.0 * 2 * PI) * 8.0;  // موجة يومية
  float noise = (random(-250, 250) / 100.0);         // ±2.5%
  float humidity = 55.0 + day_cycle + noise;
  if (humidity > 95) humidity = 95;                    // حد أعلى
  if (humidity < 20) humidity = 20;                    // حد أدنى

  // === قراءات حقيقية من النظام ===
  int rssi = WiFi.RSSI();                    // قوة إشارة WiFi
  uint32_t free_heap = ESP.getFreeHeap();    // الذاكرة الحرة الحالية
  uint32_t min_free_heap = ESP.getMinFreeHeap();  // أدنى ذاكرة حرة
  uint32_t uptime = uptime_sec;              // ثواني التشغيل

  // === بناء JSON ===
  StaticJsonDocument<768> doc;
  doc["device_id"]     = config.device_id;
  doc["session_token"] = sessionToken;

  // كائن فرعي "data"
  JsonObject data = doc.createNestedObject("data");
  data["temperature"]   = temperature;
  data["humidity"]      = humidity;
  data["chip_temp"]     = chip_temp;
  data["rssi"]          = rssi;
  data["free_heap"]     = free_heap;
  data["min_free_heap"] = min_free_heap;
  data["uptime"]        = uptime;

  char buffer[768];
  serializeJson(doc, buffer);                // JSON → String

  // === طباعة للمراقبة ===
  Serial.println("[>] Publishing sensor data:");
  Serial.printf("    Temperature: %.2f°C (chip: %.2f°C)\n", temperature, chip_temp);
  Serial.printf("    Humidity:    %.2f%%\n", humidity);
  Serial.printf("    RSSI:        %d dBm\n", rssi);
  Serial.printf("    Free Heap:   %u bytes (min: %u)\n", free_heap, min_free_heap);
  Serial.printf("    Uptime:      %u sec\n", uptime);

  // إرسال
  mqttClient.publish(topic_sensor_data.c_str(), buffer);
}

// ============================================================
//  19. معالجة الرسائل الواردة من MQTT
// ============================================================

void onMqttMessage(char* topic, byte* payload, unsigned int length) {
  Serial.printf("\n[<] Message on %s\n", topic);

  // تحليل الـ JSON
  StaticJsonDocument<768> doc;
  DeserializationError err = deserializeJson(doc, payload, length);
  if (err) {
    Serial.printf("[!] JSON parse error: %s\n", err.c_str());
    return;
  }

  // تحويل الموضوع إلى String للمقارنة
  String t = String(topic);

  // === حالة 1: رد المصادقة ===
  if (t == topic_auth_response) {
    const char* status = doc["status"];
    const char* reason = doc["reason"];
    Serial.printf("[<] Auth response: status=%s\n", status ? status : "?");

    if (doc["success"] == true) {
      // نجحت المصادقة → احفظ الـ token
      const char* token = doc["session_token"];
      if (token) {
        sessionToken  = String(token);
        tokenIssuedAt = millis();
        Serial.printf("[+] Got session token: %s...\n",
                      sessionToken.substring(0, 12).c_str());
      }
    } else {
      // فشلت → انتظر 30 ثانية قبل المحاولة
      Serial.printf("[!] Auth failed: %s\n", reason ? reason : "?");
      sessionToken = "";
      delay(30000);
    }
  }
  // === حالة 2: تأكيد استلام البيانات ===
  else if (t == topic_sensor_ack) {
    Serial.println("[+] Sensor data ACKed by server");
  }
  // === حالة 3: رفض البيانات ===
  else if (t == topic_sensor_reject) {
    const char* reason = doc["reason"];
    Serial.printf("[!] Sensor data REJECTED: %s\n", reason ? reason : "?");
    sessionToken = "";                       // امسح الرمز
    publishAuthRequest();                    // أعد المصادقة
  }
}
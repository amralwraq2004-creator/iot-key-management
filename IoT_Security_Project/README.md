# IoT Key Management System

## نظام إدارة كلمات المرور والمفاتيح الآمن لأجهزة إنترنت الأشياء

[![Python](https://img.shields.io/badge/Python-3.14-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## 📖 نظرة عامة

نظام متكامل لإدارة الأسرار في أجهزة IoT، يحمي الأسرار من:
- استخراج Firmware
- سرقة قاعدة البيانات
- هجمات MITM
- Brute-Force
- Replay Attacks

## ✨ الميزات

- ✅ **Provisioning آمن** عبر HTTPS
- ✅ **NVS Storage** مشفّر على ESP32
- ✅ **TLS 1.2+** لكل الاتصالات
- ✅ **Session Tokens** (30 دقيقة)
- ✅ **AES-256 Encryption** للأسرار المخزّنة
- ✅ **Key Rotation** دوري
- ✅ **Brute-Force Protection** (Lockout 5 دقائق)
- ✅ **Audit Logging** لكل حدث
- ✅ **Dashboard** بـ 10 صفحات
- ✅ **Remote NVS Clear** عبر MQTT
- ✅ **Multi-device Support**

## 🏗️ المعمارية

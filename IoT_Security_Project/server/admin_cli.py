import sys
from device_manager import (
    list_devices, get_device, reactivate_device,
    suspend_device, revoke_device, get_logs, reset_credential
)


def print_help():
    print("""
IoT Security System - Admin CLI
================================
Usage:
  python server/admin_cli.py list
  python server/admin_cli.py info <device_id>
  python server/admin_cli.py reactivate <device_id>
  python server/admin_cli.py suspend <device_id>
  python server/admin_cli.py revoke <device_id>
  python server/admin_cli.py reset-credential <device_id> <new_password>
  python server/admin_cli.py logs [device_id] [limit]
""")


def cmd_list():
    devices = list_devices()
    if not devices:
        print("[!] No devices registered")
        return
    print(f"\n{'DEVICE_ID':<20}{'STATUS':<15}{'FAILED':<10}{'UPDATED_AT':<30}")
    print("-" * 75)
    for d in devices:
        print(f"{d['device_id']:<20}{d['status']:<15}"
              f"{d['failed_attempts'] or 0:<10}{d['updated_at'] or '-':<30}")


def cmd_info(device_id):
    d = get_device(device_id)
    if not d:
        print(f"[!] Device not found: {device_id}")
        return
    for k, v in d.items():
        print(f"{k}: {v}")


def cmd_logs(device_id=None, limit=20):
    logs = get_logs(device_id, limit)
    if not logs:
        print("[!] No logs found")
        return
    print(f"\n{'TIMESTAMP':<32}{'DEVICE_ID':<15}{'EVENT':<25}{'DETAILS'}")
    print("-" * 100)
    for row in logs:
        print(f"{row['timestamp']:<32}{row['device_id']:<15}"
              f"{row['event_type']:<25}{row['details'] or ''}")


def main():
    args = sys.argv[1:]
    if not args:
        print_help()
        return

    command = args[0].lower()

    if command == "list":
        cmd_list()
    elif command == "info" and len(args) >= 2:
        cmd_info(args[1])
    elif command == "reactivate" and len(args) >= 2:
        reactivate_device(args[1])
    elif command == "suspend" and len(args) >= 2:
        suspend_device(args[1])
    elif command == "revoke" and len(args) >= 2:
        revoke_device(args[1])
    elif command == "reset-credential" and len(args) >= 3:
        reset_credential(args[1], args[2])
    elif command == "logs":
        device_id = args[1] if len(args) >= 2 else None
        limit = int(args[2]) if len(args) >= 3 else 20
        cmd_logs(device_id, limit)
    else:
        print_help()


if __name__ == "__main__":
    main()
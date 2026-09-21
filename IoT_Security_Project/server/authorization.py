from database import get_connection
from security_logger import log_event

def add_permission(device_id, permission_name):
    """
    إضافة صلاحية جديدة للجهاز
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO permissions (device_id, permission) VALUES (?, ?)",
            (device_id, permission_name)
        )
        conn.commit()
        log_event(device_id, "PERMISSION_ADDED", f"Permission '{permission_name}' granted.")
        return True
    except Exception as e:
        return False
    finally:
        conn.close()

def check_permission(device_id, permission_name):
    """
    التحقق مما إذا كان الجهاز يملك صلاحية معينة
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT 1 FROM permissions WHERE device_id = ? AND permission = ?",
        (device_id, permission_name)
    )
    
    result = cursor.fetchone()
    conn.close()
    
    return result is not None

def get_device_permissions(device_id):
    """
    جلب كافة الصلاحيات الخاصة بجهاز معين
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT permission FROM permissions WHERE device_id = ?",
        (device_id,)
    )
    
    rows = cursor.fetchall()
    conn.close()
    
    return [row[0] for row in rows]
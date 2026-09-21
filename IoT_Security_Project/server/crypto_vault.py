import os
from cryptography.fernet import Fernet, InvalidToken

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MASTER_KEY_PATH = os.path.join(BASE_DIR, "master.key")


def _load_master_key():
    if not os.path.exists(MASTER_KEY_PATH):
        raise FileNotFoundError(
            f"Master key not found at {MASTER_KEY_PATH}."
        )
    with open(MASTER_KEY_PATH, "r") as f:
        key = f.read().strip().encode()
    return key


_fernet = None


def _get_fernet():
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_load_master_key())
    return _fernet


def encrypt(plaintext):
    """Encrypt a string. Returns bytes."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    return _get_fernet().encrypt(plaintext)


def decrypt(ciphertext):
    """Decrypt bytes. Returns str."""
    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode("utf-8")
    try:
        return _get_fernet().decrypt(ciphertext).decode("utf-8")
    except InvalidToken:
        raise ValueError("Decryption failed: invalid token or wrong master key")


def encrypt_dict(data):
    """Encrypt a dict (converted to JSON)."""
    import json
    return encrypt(json.dumps(data))


def decrypt_dict(ciphertext):
    """Decrypt to dict."""
    import json
    return json.loads(decrypt(ciphertext))

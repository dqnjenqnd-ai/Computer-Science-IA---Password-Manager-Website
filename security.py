import os
import hashlib
import base64
import hmac # used for a safer hash comparison and nothing else
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .db import get_db_connection # the integrity check reads / writes the database


def hash_master_password(password: str) -> str:
    """SHA-256 verifier for the master password, as per the Users table design."""
    return hashlib.sha256(password.encode()).hexdigest()


# compare_digest compares the two hashes in constant time,
# so an attacker cannot learn anything from how long the comparison takes.
# Same result as "=="
def verify_master_password(password: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_master_password(password).encode(), stored_hash.encode())


def generate_salt() -> str:
    """Random salt for PBKDF2, stored in security_keys.encryption_salt."""
    return os.urandom(16).hex()


def derive_key(master_password: str, salt_hex: str) -> bytes:
    """Derives a 256-bit AES key from the master password + stored salt using PBKDF2."""
    salt = bytes.fromhex(salt_hex)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,          # 32 bytes = 256 bits, for AES-256
        salt=salt,
        iterations=390000,
    )
    return kdf.derive(master_password.encode())


def encrypt_password(plaintext: str, key: bytes) -> str:
    """AES-256-CBC encryption. Returns base64(iv + ciphertext) for storage as TEXT."""
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(iv + ciphertext).decode()


def decrypt_password(stored_value: str, key: bytes) -> str:
    """Reverses encrypt_password: splits IV back out, decrypts, unpads."""
    raw = base64.b64decode(stored_value)
    iv, ciphertext = raw[:16], raw[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode()


"""
Integrity Check

Idea: 
Keep ONE SHA-256 digest of everything in the credentials table. 
Whenever the app adds / edits / deletes an entry it recalculates and saves the digest (update_checksum).
Whenever the main page / a view page loads, the app recalculates the digest again 
    and compares it with the saved one (verify_checksum). 
If somebody changed a row directly in the database (for example in DataGrip), 
the two digests differ -> "Checksum Match? No" -> the app shows a 'Critical' message.  
"""


def compute_checksum() -> str:
    # Calculates the SHA-256 digest of all rows in the credentials table.
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, user_id, website_name, account_username, account_email, "
        "encrypted_password, note FROM credentials ORDER BY id"
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    digest = hashlib.sha256()
    for row in rows:
        line = "|".join("" if value is None else str(value) for value in row)
        digest.update(line.encode())
        digest.update(b"\n")
    return digest.hexdigest()  # 64 hex characters = varchar(64) in integrity_check


def update_checksum() -> None:
    # Saves the current digest
    # Call this after every add / edit / delete
    checksum = compute_checksum()
    conn = get_db_connection()
    cursor = conn.cursor()
    # integrity_check always holds exactly one row with id = 1, REPLACE creates or overwrites it
    cursor.execute("REPLACE INTO integrity_check (id, db_checksum) VALUES (1, %s)", (checksum,))
    conn.commit()
    cursor.close()
    conn.close()


def verify_checksum() -> bool:
    # The 'Checksum Match?' decision:
    # True = data unchanged
    # False = tampering / corruption
    current = compute_checksum()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT db_checksum FROM integrity_check WHERE id = 1")
    row = cursor.fetchone()

    if row is None:
        # First run:
        # nothing has been saved yet, so there is nothing to compare against
        cursor.close()
        conn.close()
        update_checksum()
        return True

    match = hmac.compare_digest(current.encode(), str(row[0]).encode())
    if match:
        # record when the last successful verification happened (last_verified column)
        cursor.execute("UPDATE integrity_check SET last_verified = CURRENT_TIMESTAMP WHERE id = 1")
        conn.commit()
    cursor.close()
    conn.close()
    return match
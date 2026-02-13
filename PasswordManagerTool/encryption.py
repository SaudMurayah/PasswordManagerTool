from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import os


def derive_key(passphrase, salt=None):
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    return key, salt


def encrypt_password(password, passphrase):
    key, salt = derive_key(passphrase)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(password.encode())
    combined = base64.b64encode(salt).decode() + ":" + encrypted.decode()
    return combined


def decrypt_password(encrypted_data, passphrase):
    try:
        parts = encrypted_data.split(":")
        if len(parts) != 2:
            raise ValueError("Invalid encrypted data format")
        
        salt = base64.b64decode(parts[0])
        encrypted = parts[1].encode()
        key, _ = derive_key(passphrase, salt)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted).decode()
        return decrypted
    
    except Exception as e:
        raise ValueError(f"Decryption failed: Incorrect key or corrupted data. {str(e)}")


if __name__ == "__main__":
    print("Testing Encryption Module:")
    test_password = "MySecureP@ssw0rd!"
    test_key = "my_secret_key_123"
    
    print(f"Original password: {test_password}")
    
    encrypted = encrypt_password(test_password, test_key)
    print(f"Encrypted: {encrypted}")
    
    decrypted = decrypt_password(encrypted, test_key)
    print(f"Decrypted: {decrypted}")
    
    print(f"Match: {test_password == decrypted}")

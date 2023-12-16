pip install cryptography

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    cipher = Cipher(algorithms.AES(key), modes.CFB(os.urandom(16)), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(file_path + '.enc', 'wb') as file:
        file.write(salt + ciphertext)

def decrypt_file(encrypted_file_path, password):
    with open(encrypted_file_path, 'rb') as file:
        data = file.read()
    
    salt = data[:16]
    ciphertext = data[16:]

    key = generate_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CFB(os.urandom(16)), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    decrypted_file_path = encrypted_file_path[:-4]  # Remove '.enc' from the filename
    with open(decrypted_file_path, 'wb') as file:
        file.write(plaintext)

# Example usage:
password = "your_secure_password"
file_to_encrypt = "path/to/your/file.txt"

encrypt_file(file_to_encrypt, password)

encrypted_file_path = file_to_encrypt + ".enc"
decrypt_file(encrypted_file_path, password)

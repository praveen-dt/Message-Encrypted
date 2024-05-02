from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode, urlsafe_b64decode
from os import urandom

def generate_key(password: str, salt: bytes) -> bytes:
    # Using PBKDF2HMAC for key derivation from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data: str, password: str) -> str:
    salt = urandom(16)  # Securely generate a salt
    key = generate_key(password, salt)
    fernet = Fernet(urlsafe_b64encode(key))
    encrypted_data = fernet.encrypt(data.encode())
    return urlsafe_b64encode(salt + encrypted_data).decode()

def decrypt_data(encrypted_data: str, password: str) -> str:
    data = urlsafe_b64decode(encrypted_data.encode())
    salt, encrypted_message = data[:16], data[16:]
    key = generate_key(password, salt)
    fernet = Fernet(urlsafe_b64encode(key))
    return fernet.decrypt(encrypted_message).decode()

def save_to_file(data: str, encmsg: str):
    with open(encmsg, 'w') as file:
        file.write(data)

def read_from_file(encmsg: str) -> str:
    with open(encmsg, 'r') as file:
        return file.read()

# Example usage
words = ["enroll", "tuition"]
password = "PASSWORD"
encrypted_message = encrypt_data(' '.join(words), password)

encmsg = 'encrypted_message.txt'
save_to_file(encrypted_message, encmsg)

# Read the encrypted message from a file
read_encrypted_message = read_from_file(encmsg)

# Decrypt the message
decrypted_message = decrypt_data(read_encrypted_message, password)
print("Encrypted Message:", read_encrypted_message)
print("Decrypted Message:", decrypted_message)


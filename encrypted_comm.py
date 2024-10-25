from cryptography.fernet import Fernet

# Load the key from the file
def load_fernet_key(key_file: str) -> bytes:
    """Loads the Fernet key from the specified file."""
    with open(key_file, 'rb') as key_file:
        return key_file.read()

def encrypt_message(message: str, key: bytes) -> str:
    """Encrypts the message using the provided Fernet key."""
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message.decode('utf-8')

def decrypt_message(encrypted_message: str, key: bytes) -> str:
    """Decrypts the message using the provided Fernet key."""
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message.encode())
    return decrypted_message.decode('utf-8')

"""
Crypto Tool Script:
Encrypts or decrypts files using various key types (symmetric, asymmetric, password-based).
The script supports command-line interface usage and can be imported as a module.

Usage:
    crypto_tool.py -e/d [keytype] [keyfilee/password] [input_files]
    -e/d for (e)ncrypt or (d)ecrypt
    keytype: 'sym' for symmetric, 'asym' for asymmetric, 'pwd' for password-based
    keyfile: file with en/de-cryption key or password
    input_files: Filenames to process (wildcards allowed, e.g. '*.txt')

Exit codes:
0 - Success
1 - Invalid direction or key type
2 - Password required for type 'pwd'
3 - Invalid filename or file processing error

Author: SweJob
"""

import argparse
import sys
import os
import base64
import glob
from typing import List, Tuple
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet


def get_arguments() -> Tuple[str, str, List[str], str]:
    """
    Parse command-line arguments for encryption and decryption processes.

    This method uses `argparse` to handle and validate command-line inputs 
    for the encryption tool. It determines whether the user is performing
    encryption or decryption and checks the key type and input files.

    Returns:
    -------
    tuple:
        A tuple containing:
        - key_type (str): Type of key used ('sym', 'asym', or 'pwd').
        - key_input (str): Keyfile or password input from the user.
        - input_files (list): List of filenames to process.
        - direction (str): Operation direction ('en' for encrypt, 'de' for decrypt).

    Raises:
    ------
    SystemExit:
        If an invalid direction, key type, or file is provided, the script
        exits with a specific error code.
    """

    parser = argparse.ArgumentParser(description="Encrypt or decrypt files.")

    # Define encryption and decryption flags
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', action='store_true', help="Encryption mode")
    group.add_argument('-d', action='store_true', help="Decryption mode")

    # Define the key type and keyfile/password argument
    parser.add_argument('key_type', choices=['sym', 'asym', 'pwd'],
                        help="Specify the key type: 'sym', 'asym', or 'pwd'.")
    parser.add_argument('key_input', help="Specify the keyfile or password.")

    # Define input file(s)
    parser.add_argument('input_files', nargs='+', help="List of input files to process.")

    args = parser.parse_args()

    direction = 'en' if args.e else 'de'
    return args.key_type, args.key_input, args.input_files, direction

## File handling
def read_file(filename: str) -> bytes:
    """
    Reads the content of a file in binary mode.

    Opens the specified file in binary read mode and returns its content.
    If the file is not found or cannot be read, an appropriate error message
    is displayed, and the script exits with an error code.

    Parameters:
    ----------
    filename : str
        The name of the file to read.

    Returns:
    -------
    bytes:
        The content of the file.

    Raises:
    ------
    FileNotFoundError:
        If the file does not exist.
    PermissionError:
        If there are insufficient permissions to access the file.
    IsADirectoryError:
        If the specified filename is a directory and not a file.
    """
    try:
        with open(filename, 'rb') as infile:
            return infile.read()
    except FileNotFoundError:
        print(f"Error: The file {filename} was not found.")
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied when trying to read {filename}.")
        sys.exit(1)
    except IsADirectoryError:
        print(f"Error: {filename} is a directory, not a file.")
        sys.exit(1)

def write_file(filename: str, content: bytes):
    """
    Writes the given content to a file in binary mode.

    If the file already exists, the user is prompted whether to overwrite it. 
    The file is written in binary mode.

    Parameters:
    ----------
    filename : str
        The name of the file to write to.
    content : bytes
        The binary content to be written to the file.

    Raises:
    ------
    PermissionError:
        If there are insufficient permissions to write to the file.
    IsADirectoryError:
        If the specified filename is a directory and not a file.
    """
    if os.path.exists(filename):
        response = input(f"File {filename} already exists. Overwrite? (y/n): ")
        if response.lower() != 'y':
            print(f"Aborted writing to {filename}.")
            return

    try:
        with open(filename, 'wb') as outfile:
            outfile.write(content)
    except PermissionError:
        print(f"Error: Permission denied when trying to write to {filename}.")
        sys.exit(1)
    except IsADirectoryError:
        print(f"Error: {filename} is a directory, not a file.")
        sys.exit(1)

## Loading keys from file
def load_symmetric_key(filename: str) -> bytes:
    """
    Load a symmetric key from a Base64 encoded file.

    Parameters:
    ----------
    filename : str
        Filename containing the symmetric key.

    Returns:
    -------
    bytes:
        The symmetric key.
    """
    key_data = read_file(filename)  # Use read_file to load key
    return key_data

def load_asymmetric_key(key_file: str) -> RSA.RsaKey:
    """
    Load an asymmetric RSA key from a PEM file.

    Parameters:
    ----------
    key_file : str
        Filename containing the RSA key.

    Returns:
    -------
    RSA.RsaKey:
        The loaded RSA key.

    Raises:
    ------
    ValueError:
        If the key cannot be loaded or is invalid.
    """
    key_data = read_file(key_file)  # Use read_file to load key
    try:
        return RSA.import_key(key_data)
    except ValueError as e:
        print(f"Error loading key from {key_file}: {e}")
        sys.exit(1)

## Symmetric methods
def encrypt_file_sym(filename: str, key: bytes):
    """
    Encrypts the content of a file using a symmetric key.

    This function reads the content of the specified file, encrypts it using 
    the provided symmetric key, and writes the encrypted content to a new 
    file with the '.sym.enc' suffix.

    Parameters:
    ----------
    filename : str
        The name of the file to encrypt.
    key : bytes
        The symmetric key used for encryption.

    Raises:
    ------
    IOError:
        If the file cannot be read or written to.
    """
    plaintext = read_file(filename)  # Step 1: Read the file
    ciphertext = encrypt_symmetric(plaintext, key)  # Step 2: Encrypt the content
    write_file(filename + '.sym.enc', ciphertext)  # Step 3: Write the encrypted content

def encrypt_symmetric(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypts data using the symmetric key.

    Parameters:
    ----------
    plaintext : bytes
        Data to encrypt.
    key : bytes
        Symmetric encryption key.

    Returns:
    -------
    bytes:
        Encrypted data.
    """
    fernet = Fernet(key)  # Create a Fernet instance
    return fernet.encrypt(plaintext)  # Return the encrypted content

def decrypt_file_sym(filename: str, key: bytes):
    """
    Decrypts the content of a file using a symmetric key.

    This function reads the encrypted content from the specified file, decrypts 
    it using the provided symmetric key, and writes the decrypted content to a 
    new file.

    Parameters:
    ----------
    filename : str
        The name of the file to decrypt.
    key : bytes
        The symmetric key used for decryption.

    Raises:
    ------
    IOError:
        If the file cannot be read or written to.
    """
    ciphertext = read_file(filename)  # Step 1: Read the encrypted file
    plaintext = decrypt_symmetric(ciphertext, key)  # Step 2: Decrypt the content
    write_file(filename[:-8], plaintext)  # Step 3: Write the decrypted content

def decrypt_symmetric(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypts data using the symmetric key.

    Parameters:
    ----------
    ciphertext : bytes
        Data to decrypt.
    key : bytes
        Symmetric decryption key.

    Returns:
    -------
    bytes:
        Decrypted data.
    """
    fernet = Fernet(key)  # Create a Fernet instance
    return fernet.decrypt(ciphertext)  # Return the decrypted content

## Asymmetric methods
def encrypt_file_asym(filename: str, public_key: RSA.RsaKey):
    """
    Encrypts the content of a file using an asymmetric public key.

    Parameters:
    ----------
    filename : str
        The name of the file to encrypt.
    public_key : RSA.RsaKey
        Public key for encryption.

    Raises:
    ------
    IOError:
        If the file cannot be read or written to.
    """
    plaintext = read_file(filename)  # Step 1: Read the file
    ciphertext = encrypt_asymmetric(plaintext, public_key)  # Step 2: Encrypt
    write_file(filename + '.asym.enc', ciphertext)  # Step 3: Write encrypted content

def encrypt_asymmetric(plaintext: bytes, public_key: RSA.RsaKey) -> bytes:
    """
    Encrypts data using the provided asymmetric public key.

    Parameters:
    ----------
    plaintext : bytes
        Data to encrypt.
    public_key : RSA.RsaKey
        Public key for encryption.

    Returns:
    -------
    bytes:
        Encrypted data.
    """
    cipher = PKCS1_OAEP.new(public_key)  # Create an RSA cipher instance
    return cipher.encrypt(plaintext)  # Return the encrypted data

def decrypt_file_asym(filename: str, private_key: RSA.RsaKey):
    """
    Decrypts the content of a file using an asymmetric private key.

    Parameters:
    ----------
    filename : str
        The name of the file to decrypt.
    private_key : RSA.RsaKey
        Private key for decryption.

    Raises:
    ------
    IOError:
        If the file cannot be read or written to.
    """
    ciphertext = read_file(filename)  # Step 1: Read the encrypted file
    plaintext = decrypt_asymmetric(ciphertext, private_key)  # Step 2: Decrypt
    write_file(filename[:-10], plaintext)  # Step 3: Write decrypted content

def decrypt_asymmetric(ciphertext: bytes, private_key: RSA.RsaKey) -> bytes:
    """
    Decrypts data using the provided asymmetric private key.

    Parameters:
    ----------
    ciphertext : bytes
        Data to decrypt.
    private_key : RSA.RsaKey
        Private key for decryption.

    Returns:
    -------
    bytes:
        Decrypted data.
    """
    cipher = PKCS1_OAEP.new(private_key)  # Create an RSA cipher instance
    return cipher.decrypt(ciphertext)  # Return the decrypted data

## Password-based methods
def encrypt_file_pwd(filename: str, password: str):
    """
    Encrypts the content of a file using a password-derived key.

    Parameters:
    ----------
    filename : str
        The name of the file to encrypt.
    password : str
        The password used for deriving the encryption key.

    Raises:
    ------
    IOError:
        If the file cannot be read or written to.
    """
    plaintext = read_file(filename)  # Step 1: Read the file
    salt = get_random_bytes(16)  # Generate a salt
    key = PBKDF2(password, salt, dkLen=32)  # Derive key from password
    ciphertext = encrypt_symmetric(plaintext, base64.urlsafe_b64encode(key))  # Step 2: Encrypt

    # Combine salt and ciphertext, write to file
    write_file(filename + '.pwd.enc', salt + ciphertext)  # Step 3: Write encrypted content

def encrypt_pwd(plaintext: bytes, password: str) -> bytes:
    """
    Encrypts the content of a file using a password-derived key.

    Parameters:
    ----------
    filename : str
        The name of the file to encrypt.
    password : str
        The password used for deriving the encryption key.

    Raises:
    ------
    IOError:
        If the file cannot be read or written to.
    """
    salt = get_random_bytes(16)  # Generate a salt
    key = PBKDF2(password, salt, dkLen=32)  # Derive key from password
    byte_text = plaintext
    ciphertext = encrypt_symmetric(byte_text, base64.urlsafe_b64encode(key))  # Step 2: Encrypt

    # Combine salt and ciphertext, write to file
    salted_cipher = salt + ciphertext
    return salted_cipher

def decrypt_file_pwd(filename: str, password: str):
    """
    Decrypts the content of a file using a password-derived key.

    Parameters:
    ----------
    filename : str
        The name of the file to decrypt.
    password : str
        The password used for deriving the decryption key.

    Raises:
    ------
    IOError:
        If the file cannot be read or written to.
    """
    ciphertext_with_salt = read_file(filename)  # Step 1: Read encrypted file
    salt, ciphertext = ciphertext_with_salt[:16], ciphertext_with_salt[16:]  # Extract salt

    key = PBKDF2(password, salt, dkLen=32)  # Derive key from password
    plaintext = decrypt_symmetric(bytes(ciphertext), base64.urlsafe_b64encode(key))  # Step 2: Decrypt

    write_file(filename[:-8], plaintext)  # Step 3: Write decrypted content

def decrypt_pwd(salted_cipher: bytes, password: str)-> bytes:
    """
    Decrypts the content of a file using a password-derived key.

    Parameters:
    ----------
    filename : str
        The name of the file to decrypt.
    password : str
        The password used for deriving the decryption key.

    Raises:
    ------
    IOError:
        If the file cannot be read or written to.
    """
    
    salt, ciphertext = salted_cipher[:16], salted_cipher[16:]  # Extract salt

    key = PBKDF2(password, salt, dkLen=32)  # Derive key from password
    plaintext = decrypt_symmetric(ciphertext, base64.urlsafe_b64encode(key))  # Step 2: Decrypt
    return plaintext

## Main processing logic
def process_files(
    enc_key_type: str,
    enc_key_input: str,
    enc_input_files: List[str],
    enc_direction: str
):
    """Process each input file based on the key type and operation direction.

    The function selects the appropriate encryption or decryption method
    depending on the specified key type ('sym', 'asym', or 'pwd') and
    processes each input file.

    Parameters:
    ----------
    enc_key_type : str
        The type of key being used ('sym', 'asym', 'pwd').
    enc_key_input : str
        The keyfile or password.
    enc_input_files : list
        A list of filenames to process.
    enc_direction : str
        The operation direction ('en' for encryption, 'de' for decryption).
    """
    all_files = []
    for pattern in enc_input_files:
        # Expand wildcards to list of file names
        all_files.extend(glob.glob(pattern))

    for filename in all_files:
        if enc_key_type == 'sym':
            key = load_symmetric_key(enc_key_input)
            if enc_direction == 'en':
                encrypt_file_sym(filename, key)
            else:
                decrypt_file_sym(filename, key)

        elif enc_key_type == 'asym':
            if enc_direction == 'en':
                public_key = load_asymmetric_key(enc_key_input)
                encrypt_file_asym(filename, public_key)
            else:
                private_key = load_asymmetric_key(enc_key_input)
                decrypt_file_asym(filename, private_key)

        elif enc_key_type == 'pwd':
            if enc_direction == 'en':
                encrypt_file_pwd(filename, enc_key_input)
            else:
                decrypt_file_pwd(filename, enc_key_input)

        print(f"Processed {filename} ({enc_direction}cryption completed).")


if __name__ == '__main__':
    key_type_main, key_input_main, input_files_main, direction_main = get_arguments()
    process_files(key_type_main, key_input_main, input_files_main, direction_main)

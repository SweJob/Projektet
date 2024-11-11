# crypto_tool.py - by Jonas "SweJob" Bergstedt
The crypto_tool.py script enables encryption and decryption of files using symmetric, asymmetric, or password-based keys.  
It supports command-line interface usage and can also be imported as a module
[Command line](#command-line)

## General overview
### Program structure
Simple architechture with a general approach. 
Functions to read symmetric and assymetric keys,
Functions to read and write a file as bytes. These read/write data and keys
Functions to en-/decrypt with the 3 different methods.
Functions to combine reading file , en-/decrypt it, and write it to a new file.

The password en-/decryption functions create a hash from the password and uses it as a key for assymetric encryption

### Usage
#### Command Line
To run the crypto_tool it needs the following information:
-e/-d : En-/decrypt the file
sym/asym/passwd :  type of en-/decryption
keyfile/password : file with key or the password to generate the key from
input_files : the file to en-/decrypt
`python crypto_tool.py -e/-d [keytype] [keyfile/password] [input_files...]`

No default values for arguments.

##### Command line examples
1. **Encrypt a File with Symmetric Key:**  
   `python crypto_tool.py -e sym my_symmetric_key.key myfile.txt`  
   This command encrypts myfile.txt using the symmetric key stored in my_symmetric_key.key.
2. **Decrypt a File with Symmetric Key:**  
   `python crypto_tool.py -d sym my_symmetric_key.key myfile.txt.sym.enc`  
   This command decrypts myfile.txt.sym.enc using the symmetric key stored in my_symmetric_key.key.
3. **Encrypt a File with Asymmetric Public Key:**  
   `python crypto_tool.py -e asym my_asymmetric_key.pub myfile.txt`  
   This command encrypts myfile.txt using the public key stored in my_asymmetric_key.pub.
4. **Decrypt a File with Asymmetric Private Key:**  
   `python crypto_tool.py -d asym my_asymmetric_key.pem myfile.txt.asym.enc`  
   This command decrypts myfile.txt.asym.enc using the private key stored in my_asymmetric_key.pem.
5. **Encrypt a File with Password:**  
   `python crypto_tool.py -e pwd mypassword myfile.txt`  
   This command encrypts myfile.txt using mypassword.
6. **Decrypt a File with Password:**  
   `python crypto_tool.py -d pwd mypassword myfile.txt.pwd.enc`  
   This command decrypts myfile.txt.pwd.enc using mypassword.
   
#### Using Functions
To use the functions to en/decrypt data, just use the various encrypt/decrypt functions.
Add data to en-/decrypt as bytes and a key/password to the function. 
The data is returned as bytes. (for password fucntions the encrypted data has the salt added to the start)

##### Function headers
def encrypt_symmetric(plaintext: bytes, key: bytes) -> bytes:
def decrypt_symmetric(ciphertext: bytes, key: bytes) -> bytes:

def encrypt_asymmetric(plaintext: bytes, public_key: RSA.RsaKey) -> bytes:
def decrypt_asymmetric(ciphertext: bytes, private_key: RSA.RsaKey) -> bytes:

def encrypt_pwd(plaintext: bytes, password: str) -> bytes:
def decrypt_pwd(salted_cipher: bytes, password: str)-> bytes:

### Notes  
Ensure that the necessary libraries (e.g., pycryptodome, cryptography) are installed before running the script.  
For Windows users, it may be necessary to use python instead of python3, depending on your environment.

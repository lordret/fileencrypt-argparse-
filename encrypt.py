import os
import sys
import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

def generate_key(password):
    salt = b'salt_'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_file(key, in_file, out_file=None):
    if not out_file:
        out_file = in_file + '.encrypted'

    with open(in_file, 'rb') as f:
        data = f.read()

    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)

    with open(out_file, 'wb') as f:
        f.write(encrypted)

    return out_file

def decrypt_file(key, in_file, out_file=None):
    if not out_file:
        out_file = os.path.splitext(in_file)[0]

    with open(in_file, 'rb') as f:
        data = f.read()

    fernet = Fernet(key)
    decrypted = fernet.decrypt(data)

    with open(out_file, 'wb') as f:
        f.write(decrypted)

    return out_file

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='File encryption tool')
    parser.add_argument('-m', '--mode', type=str, choices=['encrypt', 'decrypt'], help='Encryption or decryption mode')
    parser.add_argument('-p', '--password', type=str, required=True, help='Password to use for encryption/decryption')
    parser.add_argument('-i', '--input', type=str, required=True, help='Input file to encrypt/decrypt')
    parser.add_argument('-o', '--output', type=str, help='Output file (defaults to <input_file>.encrypted or <input_file>.decrypted)')
    args = parser.parse_args()

    key = generate_key(args.password.encode())

    if args.mode == 'encrypt':
        encrypt_file(key, args.input, args.output)
    elif args.mode == 'decrypt':
        decrypt_file(key, args.input, args.output)
    else:
        print('Invalid mode')
        sys.exit(1)


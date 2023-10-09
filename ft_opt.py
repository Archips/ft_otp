#!/usr/bin/env python3

import os
import re
import argparse
from cryptography.fernet import Fernet

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-g", help="hexadecimal key of 64 characters")
    parser.add_argument("-k", help="generate a otp based on the key given in argument")
    args = parser.parse_args()

    if not args.g and not args.k:
        parser.error("ft_opt takes at least one argument -g or -k")
        exit(1)

    return args


def is_valid_hex_key(key):
    
    pattern = re.compile(r'^[0-9a-fA-F]{64}$')
    return bool(pattern.match(key))

def check_hex(key):

    if is_valid_hex_key(key):
        return key
    else:
        try:
            with open(key) as k:
                if k:
                    secret = k.read()
                    if is_valid_hex_key(secret):
                        return secret
        except:
            print("ft_opt.py : error : invalid")
    print("ft_opt.py : error : invalid")

def check_key(key):

    if key.endswith(".key") and os.access(key, os.R_OK):
        return True
    return False

def fernet_encrypt(key):

    fernet_key = Fernet.generate_key()

    try:
        with open('.master_key.key', 'wb') as master_key:
            master_key.write(fernet_key)
    except:
        print("ft_opt.py : error : master key coudl not be generated")

    with open('.master_key.key', 'rb') as key_file:
        master_key = key_file.read()

    fernet = Fernet(master_key)

    encrypted = fernet.encrypt(bytes(key, 'utf-8'))

    try:
        with open('ft_opt.key', 'wb') as encrypted_file:
            encrypted_file.write(encrypted)
    except:
        print("ft_opt.py : error : encryption failed")


def fernet_decrypt(encrypt_key):

    try:
        with open('.master_key.key', 'rb') as master_key:
            fernet_key = master_key.read()
    except:
        print("ft_opt.py : error : invalid master key")

    fernet = Fernet(fernet_key)

    with open(encrypt_key, 'rb') as encrypted_file:
        encrypted = encrypted_file.read()

    decrypted = fernet.decrypt(encrypted)

    with open('decrypted_key.hex', 'wb') as decrypted_file:
        decrypted_file.write(decrypted)

if __name__ == "__main__":

    args = parse_arguments()

    if args.g and check_hex(args.g):
        encrypted_hex = check_hex(args.g)
        fernet_encrypt(encrypted_hex)
    if args.k and check_key(args.k):
        fernet_decrypt(args.k)

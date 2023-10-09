#!/usr/bin/env python3

import os
import re
import hmac
import math
import time
import hashlib
import argparse
import readline
from pathlib import Path
from cryptography.fernet import Fernet
from pynput.keyboard import Key, Controller

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-g", help="hexadecimal key of 64 characters")
    parser.add_argument("-k", help="generate a otp based on the key given in argument")
    args = parser.parse_args()

    if not args.g and not args.k:
        parser.error("ft_otp takes at least one argument -g or -k")
        exit(1)

    return args

def wipe_cli_history():
    
    try:
        with open('~/.zsh_history', 'r') as zh:
            data = zh.read()
            if data:
                lines = data.split('\n')
                to_be_wiped = lines[-1]
                print(to_be_wiped)
    except:
        print("ft_otp.py : error : could not access zsh history")


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
            print("ft_otp.py : error : invalid")
    print("ft_otp.py : error : invalid")

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
        print("ft_otp.py : error : master key coudl not be generated")
        exit(1)
    with open('.master_key.key', 'rb') as key_file:
        master_key = key_file.read()

    fernet = Fernet(master_key)

    encrypted = fernet.encrypt(bytes(key, 'utf-8'))

    try:
        with open('ft_otp.key', 'wb') as encrypted_file:
            encrypted_file.write(encrypted)
    except:
        print("ft_otp.py : error : encryption failed")
        exit(1)

def fernet_decrypt(encrypt_key):

    try:
        with open('.master_key.key', 'rb') as master_key:
            fernet_key = master_key.read()
    except:
        print("ft_otp.py : error : invalid master key")
        exit(1)

    fernet = Fernet(fernet_key)

    with open(encrypt_key, 'rb') as encrypted_file:
        encrypted = encrypted_file.read()

    decrypted = fernet.decrypt(encrypted)

    # with open('decrypted_key.hex', 'wb') as decrypted_file:
    #     decrypted_file.write(decrypted)

def ft_otp(encrypt_key, len: int = 6):

    now = math.floor(time.time())
    step = 30
    t = math.floor(now / step)
    shared_key = fernet_decrypt(encrypt_key)
    hash = hmac.new(bytes(str(shared_key), 'utf-8'), t.to_bytes(length = 8, byteorder="big"), hashlib.sha256)
    return dynamic_truncation(hash, len)

def dynamic_truncation(hash: hmac.HMAC, len: int):
    
    bitstring = bin(int(hash.hexdigest(), base=16))
    # >> 11010100000110011101010100010001100100011111001010111010001010110110000010111101000101011110111111010111101100011101001111100001011111101100001011110111100111001111100000100010011001010110101111100010111001001000010000011000000010010111100110101100011
    last_four_bits = bitstring[-4:]
    # >> 0011
    offset = int(last_four_bits, base=2)
    # >> 3
    chosen_32_bits = bitstring[offset * 8 : offset * 8 + 32]
    # >> 01000100011001000111110010101110
    full_totp = str(int(chosen_32_bits, base=2))
    # >> 1147436206
    return full_totp[-len:]
    # >> 436206

if __name__ == "__main__":

    args = parse_arguments()

    if args.g and check_hex(args.g):
        readline.clear_history()
        # os.system('clear')
        # os.system('history')
        encrypted_hex = check_hex(args.g)
        fernet_encrypt(encrypted_hex)
        file = Path(args.g)
        if file.is_file():
            os.remove(file)
    if args.k and check_key(args.k):
        print(ft_otp(args.k))

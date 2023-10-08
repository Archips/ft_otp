#!/usr/bin/env python3

import os
import re
import argparse

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
        return True
    else:
        try:
            with open(key) as k:
                if k:
                    secret = k.read()
                    if is_valid_hex_key(secret):
                        return True
        except:
            return False
    return False

def check_key(key):

    if key.endswith(".key") and os.access(key, os.R_OK):
        return True
    return False

if __name__ == "__main__":

    args = parse_arguments()

    if args.g and check_hex(args.g):
        print(True)
    if args.k and check_key(args.k):
        print(True)

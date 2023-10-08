#!/usr/bin/env python3

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

if __name__ == "__main__":

    args = parse_arguments()

    print("hello")
    print(args.g)
    print(args.k)

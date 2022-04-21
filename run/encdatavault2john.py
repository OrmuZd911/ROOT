#!/usr/bin/env python3

# Helper script for cracking ENCSecurity DataVault.
#
# This software is Copyright (c) 2021, Sylvain Pelissier <sylvain.pelissier at kudelskisecurity.com>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

import sys
import binascii
import os  
from pathlib import Path


def process(vault):
    salt = None

    if not os.path.isdir(vault):  
        sys.stderr.write(f"{vault} : should be a folder.\n")
        sys.exit(1)

    file_list = os.listdir(vault)
    if "filesystem.dat" in file_list:
        # Sandisk, Sony vault or ENCSecurity user password.
        file_path = Path(vault) / "filesystem.dat"

    elif "index.dat" in file_list and "keychain.dat" in file_list:
        # ENCSecurity vault.
        file_path = Path(vault) / "index.dat"
    else:
        sys.stderr.write(f"{vault} : Valid vault not found.\n")
        return
    
    with open(file_path, "rb") as f:
        header = f.read(4)                  # Read header
        if header == b'\xd2\xc3\xb4\xa1':   # Test if we have a valid header
            version = int.from_bytes(f.read(4),byteorder="little")
            crypto = int.from_bytes(f.read(4),byteorder="little")
            iv = binascii.hexlify(f.read(8))
            header_enc = binascii.hexlify(f.read(4))
        else:
            sys.stderr.write(f"{file_list[0]} : Valid header not found.\n")
            return

        if len(header_enc) != 8:
            sys.stderr.write(f"{file_list[0]} : Problem reading encrypted header.\n")
            return

    sys.stdout.write(f"{vault}:$encdv${version}${crypto}${iv.decode()}${header_enc.decode()}")

    if version == 3:
        with open(Path(vault) / "keychain.dat", "rb") as f:
            f.seek(16)
            keychain = binascii.hexlify(f.read(128))
            sys.stdout.write(f"${keychain.decode()}\n")
    else:
        sys.stdout.write("\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write(f"Usage: {sys.argv[0]} <vault folder>\n")
        sys.stderr.write(f"\nExample: {sys.argv[0]} vault/\n")
        sys.exit(1)

    process(sys.argv[1])

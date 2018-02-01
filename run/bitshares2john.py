#!/usr/bin/env python

# Script to extract "hashes" from BitShares databases.
#
# Tested with BitShares.Setup.2.0.180115.exe on Windows 7 SP1.
#
# Location for databases -> %APPDATA%\BitShares2-light\databases\file__0\{1,2...}
#
# "Local Wallet" on https://wallet.bitshares.org for Google Chrome ->
# ~/.config/google-chrome/Default/databases/https_wallet.bitshares.org_0
#
# Metadata extraction:
#
# $ sqlite3 Databases.db
# sqlite> select * from Databases;
# 1|file__0|__sysdb__|System Database|4194304
# 2|file__0|graphene_db_4018d7|graphene_db_4018d7|4194304
# 3|file__0|graphene_v2_4018d7_default|graphene_v2_4018d7_default|4194304
# 4|file__0|graphene_v2_4018d7_openwall|graphene_v2_4018d7_openwall|4194304
#
# Hash extraction:
#
# $ sqlite3 file__0/4
# sqlite> select * from wallet;
# 3-openwall|{"public_name":"openwall", ..., "encryption_key":"ec4...", ...}
#
# This software is Copyright (c) 2017, Dhiru Kholia <dhiru at openwall.com> and
# it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

import os
import sys
import json
import sqlite3
import binascii
import traceback

PY3 = sys.version_info[0] == 3

if not PY3:
    reload(sys)
    sys.setdefaultencoding('utf8')


def process_file(filename):
    try:
        db = sqlite3.connect(filename)
        cursor = db.cursor()
        rows = cursor.execute("SELECT key, value from wallet")
    except:
        traceback.print_exc()
        return
    for row in rows:
        name, value = row
        data = json.loads(value)
        if "encryption_key" not in data:
            continue
        encryption_key = data["encryption_key"]
        sys.stdout.write("%s:$BitShares$0*%s\n" % (name, encryption_key))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [BitShares SQLite file(s)]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])

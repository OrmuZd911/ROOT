#!/usr/bin/env python3

# This software is Copyright (c) 2024, k4amos <k4amos at proton.me>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

# This script is essentially a python version of radius2john.pl written by Didier ARENZANA. 
# The previous version of radius2john.py was written by Maxime GOYETTE <maxgoyette0-at-gmail.com>

# ---

# Utility to bruteforce RADIUS shared-secret
# Usage: ./radius2john.py <pcap files>
#
# This script depends on Scapy (https://scapy.net)
# To install: pip install --user scapy

# ---

# Application of two  methods described in http://www.untruth.org/~josh/security/radius/radius-auth.html :
# "3.3 User-Password Attribute Based Shared Secret Attack"
# "3.1 Response Authenticator Based Shared Secret Attack"

# For attack 3.3 :
# we try authentications using a known password, and sniff the radius packets to a pcpap file.
# This script reads access-request in the pcap file, and dumps the md5(RA+secret) and RA, in a john-friendly format.
# The password must be always the same, be less then 16 bytes long, and entered in the $PASSWORD variable below.
# The user names used during this attack must be entered in @LOGINS below.

# For attack 3.1:
# we don't need to try authentications. Just sniff the radius packets in a pcap file.
# This script reads the pcap file, matches radius responses with the corresponding all_requests,
# and dumps md5 and salt as needed.

import scapy.all as scapy
import binascii
import sys


# Global variables
PASSWORD = b"1"  # The user password used for the 3.3 attack
LOGINS = ["max"]  # The user logins used for the 3.3 attack
UNIQUE = 1  # Set to 0 to disable unicity of client IPs in the output file
VALID_LOGIN = {login: True for login in LOGINS}

all_requests = {}
dumped_ips = {}


def read_file(filename):
    packets = scapy.rdpcap(filename)
    for packet in packets:
        process_packet(packet)


def process_packet(packet):
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.UDP):
        ip_layer = packet[scapy.IP]
        udp_layer = packet[scapy.UDP]

        if udp_layer.dport in [1812, 1813] or udp_layer.sport in [1812, 1813]: 
            radius_data = bytes(udp_layer.payload)
            process_radius(ip_layer, radius_data, bytes(udp_layer.payload))


def process_radius(ip, radius_data, udpdata):
    radius_packet = scapy.Radius(radius_data)

    if radius_packet.code in [1, 4]:  # Access-Request, Accounting-Request

        user_name, user_password = None, None
        for _ in range(len(radius_packet.attributes)):
            if radius_packet.attributes[_].name == "User-Name":
                user_name = radius_packet.attributes[_].value.decode("utf-8")

            if radius_packet.attributes[_].name == "User-Password":
                user_password = radius_packet.attributes[_].value.decode("utf-8")

        if user_name in VALID_LOGIN and user_password:
            dump_access_request(
                ip.src, user_name, radius_packet.authenticator, user_password
            )

        all_requests[f"{ip.src}-{radius_packet.id}"] = radius_packet.authenticator

    elif radius_packet.code in [2, 11, 3, 5]:  # Access-Accept, Access-Challenge, Access-Reject, Accounting-Response
        key = f"{ip.dst}-{radius_packet.id}"
        if key in all_requests:
            dump_response(ip.dst, all_requests[key], radius_packet, udpdata)


def dump_response(ip, req_ra, radius_packet, udpdata):  # 3.1 attack
    if UNIQUE and ip in dumped_ips:
        return

    hash_val = radius_packet.authenticator

    salt = bytearray(udpdata)
    salt[4:20] = req_ra  # Replace Response Authenticator with the Request Authenticator

    response_type = "1009" if len(salt) <= 16 else "1017"
    print(
        f"{ip}:$dynamic_{response_type}${binascii.hexlify(hash_val).decode()}$HEX${binascii.hexlify(salt).decode('utf-8')}"
    )

    dumped_ips[ip] = "reply"


def dump_access_request(ip, login, ra, hashed):  # 3.3 attack
    if UNIQUE and ip in dumped_ips and dumped_ips[ip] == "request":
        return

    xor_result = bytes(a ^ b for a, b in zip(hashed, PASSWORD))
    print(
        f"{ip}:$dynamic_1008${binascii.hexlify(xor_result).decode()}$HEX${binascii.hexlify(ra).decode('utf-8')}"
    )

    dumped_ips[ip] = "request"


if __name__ == "__main__":

    try:
        import scapy.all as scapy
    except ImportError:
        print(
            "Scapy seems to be missing, run 'pip install --user scapy' to install it"
        )
        exit(1)

    if len(sys.argv) > 1 and "-h" not in sys.argv and "--help" not in sys.argv:
        for filename in sys.argv[1:]:
            read_file(filename)
    else:
        print(
            "Utility to bruteforce RADIUS shared-secret written by k4amos \nUsage: ./radius2john.py <pcap files>"
        )
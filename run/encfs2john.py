#!/usr/bin/env python

"""encfs2john.py processes EncFS files into a format suitable
for use with JtR"""


from xml.etree.ElementTree import ElementTree
import sys
import base64
import binascii
import os


def process_folder(folder):
    filename = os.path.join(folder, ".encfs6.xml")
    if not os.path.exists(filename):
        print >> sys.stderr, "%s doesn't have .encfs6.xml!" % folder
        return 1
    mf = open(filename)
    tree = ElementTree()
    tree.parse(mf)
    r = tree.getroot()
    elements = list(r.iter())
    cipher = None
    keySize = None
    iterations = None
    salt = None
    saltLen = None
    dataLen = None
    data = None
    for element in elements:
        if element.tag == "keySize":
            keySize = element.text
            if not keySize.isdigit():
                print >> sys.stderr, "%s contains bad keySize" % filename
                return
        if element.tag == "kdfIterations":
            iterations = element.text
            if not iterations.isdigit():
                print >> sys.stderr, "%s contains bad iterations" % filename
                return
        if element.tag == "name" and not cipher:
            cipher = element.text
        if element.tag == "saltData":
            salt = element.text
        if element.tag == "saltLen":
            saltLen = element.text
        if element.tag == "encodedKeySize":
            dataLen = element.text
        if element.tag == "encodedKeyData":
            data = element.text

    if not cipher or not keySize or not iterations or not salt or not saltLen or not dataLen or not data:
        print >> sys.stderr, "%s contains bad data, please report this if target contains valid EncFS data" % filename
        return

    if cipher.upper().find("AES") > -1:
        cipher = 0
    print "%s:$encfs$%s*%s*%s*%s*%s*%s*%s" % (folder, keySize, iterations, cipher,
            saltLen, binascii.hexlify(base64.decodestring(salt)), dataLen,
            binascii.hexlify(base64.decodestring(data)))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print >> sys.stderr, "Usage: %s <EncFS folder>" % sys.argv[0]
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_folder(sys.argv[i])

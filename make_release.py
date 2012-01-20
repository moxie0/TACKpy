#! /usr/bin/env python

fnames = [\
"src/numbertheory.py",
"src/ellipticcurve.py",
"src/ecdsa.py",
"src/rijndael.py",
"src/misc.py",
"src/compat.py",
"src/cryptomath.py",
"src/time_funcs.py",
"src/asn1.py",
"src/pem.py",
"src/m2crypto.py",
"src/aes_wrappers.py",
"src/ecdsa_wrappers.py",
"src/struct_parser.py",
"src/constants.py",
"src/tack_structures.py",
"src/ssl_cert.py",
"src/keyfile.py",
"src/main.py"] 

# Stitch the source files together, ommitting anything before 
# the ######... header (usually just import statements) necessary 
# for when this is separate modules

s = open("src/header.py").read()
for fname in fnames:
    s2 = open(fname).read()
    i = s2.find("################ ")
    assert(i != -1)
    s2 = s2[i:]
    if s2[-1] != "\n":
        s2 += "\n"
    s += s2
print s
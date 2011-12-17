#! /usr/bin/env python

fnames = [\
"numbertheory.py",
"ellipticcurve.py",
"ecdsa.py",
"rijndael.py",
"compat.py",
"cryptomath.py",
"ecdsa_wrappers.py",
"time_funcs.py",
"pem.py",
"struct_parser.py",
"asn1_parser.py",
"constants.py",
"tack_structures.py",
"ssl_cert.py",
"tack_cert.py",
"keyfile.py",
"tests.py",
"main.py"] 


s = open("header.py").read()
for fname in fnames:
    s2 = open(fname).read()
    i = s2.find("################ ")
    assert(i != -1)
    s2 = s2[i:]
    s += s2
print s
#! /usr/bin/env python

fnames = [\
"TACKpy/version.py",
"TACKpy/numbertheory.py",
"TACKpy/ellipticcurve.py",
"TACKpy/ecdsa.py",
"TACKpy/rijndael.py",
"TACKpy/misc.py",
"TACKpy/compat.py",
"TACKpy/cryptomath.py",
"TACKpy/time_funcs.py",
"TACKpy/asn1.py",
"TACKpy/pem.py",
"TACKpy/m2crypto.py",
"TACKpy/aes_wrappers.py",
"TACKpy/ecdsa_wrappers.py",
"TACKpy/struct_parser.py",
"TACKpy/constants.py",
"TACKpy/tack_structures.py",
"TACKpy/ssl_cert.py",
"TACKpy/keyfile.py",
"TACKpy/test.py",
"TACKpy/main.py"] 

# Stitch the source files together, ommitting anything before 
# the ######... header (usually just import statements) necessary 
# for when this is separate modules

s = open("TACKpy/header.py").read()
for fname in fnames:
    s2 = open(fname).read()
    i = s2.find("################ ")
    assert(i != -1)
    s2 = s2[i:]
    if s2[-1] != "\n":
        s2 += "\n"
    s += s2
print s
from compat import *

################ PEM ###

import binascii

def dePem(b, name):
    start = b.find(bytearray("-----BEGIN %s-----" % name, "ascii"))
    end = b.find(bytearray("-----END %s-----" % name, "ascii"))
    if start == -1:
        raise SyntaxError("Missing PEM prefix")
    if end == -1:
        raise SyntaxError("Missing PEM postfix")
    b = b[start+len(bytearray("-----BEGIN %s-----" % name, "ascii")) : end]
    return bytearray(binascii.a2b_base64(b))

def pem(b, name):
    s1 = b2a_base64(b)[:-1] # remove terminating \n
    s2 = ""
    while s1:
        s2 += s1[:64] + "\n"
        s1 = s1[64:]
    b = (bytearray("-----BEGIN %s-----\n" % name, "ascii")) + \
            bytearray(s2, "ascii") + \
            (bytearray("-----END %s-----" % name, "ascii"))     
    return b



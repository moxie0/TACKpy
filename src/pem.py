from compat import *

################ PEM ###

import binascii

def dePem(b, name):
    """Decode a PEM bytearray into a bytearray of its payload.
    
    The input must contain an appropriate PEM prefix and postfix
    based on the input name string, e.g. for name="CERTIFICATE":

    -----BEGIN CERTIFICATE-----
    MIIBXDCCAUSgAwIBAgIBADANBgkqhkiG9w0BAQUFADAPMQ0wCwYDVQQDEwRUQUNL
    MB4XDTAxMDcwNTE4MDU0OFoXDTM0MDcwNDE4MDU0OFowDzENMAsGA1UEAxMEVEFD
    SzAfMA0GCSqGSIb3DQEBAQUAAw4AMAsCBAECAwQCAwEAAaOBxzCBxDCBwQYJKwYB
    BAGCsDQBBIGzAQu20/jhl9Y336TWuuETbtskDAcZrG1Od4zFXhF2n5UjD3fbiiOk
    VfVNxopxZX7nGWZXWSHw4p6fGzAHPpSNLZFATXgHsiLKCgIBtVZjABj4p6FRtOwo
    CJgJPfW9U3ygmcwndAXQKB3g2t/RRCDajipxepNH1iwob4nI6OsMIEreq9Fl4yZZ
    aV2+DP4/Qm0vDIVVe43VDpAgIZTqtXchp4xA9e5Nftr7LQ6ZetDyiQAAAAUwDQYJ
    KoZIhvcNAQEFBQADAwA5kw==
    -----END CERTIFICATE-----    

    The first such PEM block in the input will be found, and its
    payload will be base64 decoded and returned.
    """
    start = b.find(bytearray("-----BEGIN %s-----" % name, "ascii"))
    end = b.find(bytearray("-----END %s-----" % name, "ascii"), start)
    if start == -1:
        raise SyntaxError("Missing PEM prefix")
    if end == -1:
        raise SyntaxError("Missing PEM postfix")
    b = b[start+len(bytearray("-----BEGIN %s-----" % name, "ascii")) : end]
    return bytearray(binascii.a2b_base64(b))

def pem(b, name):
    """Encode a payload bytearray into a PEM bytearray.
    
    The input will be base64 encoded, then wrapped in a PEM prefix/postfix
    based on the name string, e.g. for name="CERTIFICATE":
    
    -----BEGIN CERTIFICATE-----
    MIIBXDCCAUSgAwIBAgIBADANBgkqhkiG9w0BAQUFADAPMQ0wCwYDVQQDEwRUQUNL
    MB4XDTAxMDcwNTE4MDU0OFoXDTM0MDcwNDE4MDU0OFowDzENMAsGA1UEAxMEVEFD
    SzAfMA0GCSqGSIb3DQEBAQUAAw4AMAsCBAECAwQCAwEAAaOBxzCBxDCBwQYJKwYB
    BAGCsDQBBIGzAQu20/jhl9Y336TWuuETbtskDAcZrG1Od4zFXhF2n5UjD3fbiiOk
    VfVNxopxZX7nGWZXWSHw4p6fGzAHPpSNLZFATXgHsiLKCgIBtVZjABj4p6FRtOwo
    CJgJPfW9U3ygmcwndAXQKB3g2t/RRCDajipxepNH1iwob4nI6OsMIEreq9Fl4yZZ
    aV2+DP4/Qm0vDIVVe43VDpAgIZTqtXchp4xA9e5Nftr7LQ6ZetDyiQAAAAUwDQYJ
    KoZIhvcNAQEFBQADAwA5kw==
    -----END CERTIFICATE-----    
    """
    s1 = b2a_base64(b)[:-1] # remove terminating \n
    s2 = ""
    while s1:
        s2 += s1[:64] + "\n"
        s1 = s1[64:]
    s = ("-----BEGIN %s-----\n" % name) + s2 + \
        ("-----END %s-----\n" % name)     
    return s



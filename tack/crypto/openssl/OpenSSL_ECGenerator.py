import math, ctypes
from tack.compat import bytesToStr
from .OpenSSL_ECPublicKey import OpenSSL_ECPublicKey
from .OpenSSL_ECPrivateKey import OpenSSL_ECPrivateKey
from .OpenSSL import openssl as o

class OpenSSL_ECGenerator:
    
    @staticmethod
    def generateECKeyPair():
        try:
            ec_key, ec_group = None, None

            # Generate the new key
            ec_key = o.EC_KEY_new_by_curve_name(o.OBJ_txt2nid("prime256v1"))
            o.EC_KEY_generate_key(ec_key)

            # Extract the key's public and private values as strings
            # into pubBuf and privBuf
            pubBuf = bytesToStr(bytearray(1+64)) # [0x04] ...
            privBuf = bytesToStr(bytearray(32))

            ec_point = o.EC_KEY_get0_public_key(ec_key)
            ec_group = o.EC_GROUP_new_by_curve_name(o.OBJ_txt2nid("prime256v1"))            
            o.EC_POINT_point2oct(ec_group, ec_point, o.POINT_CONVERSION_UNCOMPRESSED, pubBuf, 65, None)

            bignum = o.EC_KEY_get0_private_key(ec_key)
            privLen = o.BN_bn2bin(bignum, privBuf)

            # Convert the public and private keys into fixed-length 64 and 32 byte arrays
            # Leading zeros are added to priv key, leading byte (0x04) stripped from pub key
            rawPublicKey =  bytearray(pubBuf[1:65])
            rawPrivateKey = bytearray(32-privLen) + bytearray(privBuf[:privLen])

            return (OpenSSL_ECPublicKey(rawPublicKey, ec_key), 
                    OpenSSL_ECPrivateKey(rawPrivateKey, rawPublicKey, ec_key))
        finally:
            o.EC_KEY_free(ec_key)
            o.EC_GROUP_free(ec_group)

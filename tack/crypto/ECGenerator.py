
import ctypes, sys
from tack.compat import bytesToStr
from tack.crypto.ASN1 import ASN1Parser, fromAsn1IntBytes
from tack.crypto.ECPrivateKey import ECPrivateKey
from tack.crypto.ECPublicKey import ECPublicKey
from tack.crypto.OpenSSL import openssl as o
from tack.util.PEMDecoder import PEMDecoder

class ECGenerator:

    def generateECKeyPair(self):
        try:
            ec_key, ec_group = None, None

            # Generate the new key
            ec_key = o.EC_KEY_new_by_curve_name(o.OBJ_txt2nid("prime256v1"))
            o.EC_KEY_generate_key(ec_key)

            # Extract the key's public and private values as byte strings
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

            return (ECPublicKey(rawPublicKey, ec_key), 
                    ECPrivateKey(rawPrivateKey, rawPublicKey, ec_key))
        finally:
            o.EC_KEY_free(ec_key)
            o.EC_GROUP_free(ec_group)
        


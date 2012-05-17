# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

import ctypes
from tack.crypto.Digest import Digest
from .OpenSSL_ECPublicKey import OpenSSL_ECPublicKey
from tack.crypto.python.Python_ECPublicKey import Python_ECPublicKey
from .OpenSSL import openssl as o
from .OpenSSL import bytesToC, cToBytes


class OpenSSL_ECPrivateKey:

    def __init__(self, rawPrivateKey, rawPublicKey, ec_key=None):
        self.ec_key = None # In case of early destruction
        assert(rawPrivateKey is not None and rawPublicKey is not None)
        assert(len(rawPrivateKey)==32 and len(rawPublicKey) == 64)

        self.rawPrivateKey = rawPrivateKey
        self.rawPublicKey  = rawPublicKey
        if ec_key:
            self.ec_key = o.EC_KEY_dup(ec_key)
        else:
            self.ec_key =  self._constructEcFromRawKey(self.rawPrivateKey)

    def __del__(self):
        o.EC_KEY_free(self.ec_key)

    def sign(self, data):        
        try:
            ecdsa_sig = None

            # Hash and apply ECDSA
            hashBuf = bytesToC(Digest.SHA256(data))
            ecdsa_sig = o.ECDSA_do_sign(hashBuf, 32, self.ec_key)
            
            # Encode the signature into 64 bytes
            rBuf = bytesToC(bytearray(32))
            sBuf = bytesToC(bytearray(32))
            
            rLen = o.BN_bn2bin(ecdsa_sig.contents.r, rBuf)
            sLen = o.BN_bn2bin(ecdsa_sig.contents.s, sBuf)
            
            rBytes = bytearray(32-rLen) + cToBytes(rBuf)[:rLen]
            sBytes = bytearray(32-sLen) + cToBytes(sBuf)[:sLen]
            sigBytes = rBytes + sBytes   
            assert(len(sigBytes) == 64)
        finally:
            o.ECDSA_SIG_free(ecdsa_sig)

        # Double-check the signature before returning
        assert(OpenSSL_ECPublicKey(self.rawPublicKey).verify(data, sigBytes))
        return sigBytes

    def getRawKey(self):
        return self.rawPrivateKey
        
    def _constructEcFromRawKey(self, rawPrivateKey):
        try:
            privBignum, ec_key = None, None
            
            ec_key = o.EC_KEY_new_by_curve_name(o.OBJ_txt2nid(b"prime256v1"))
            privBuf = bytesToC(rawPrivateKey)
            privBignum = o.BN_new()
            o.BN_bin2bn(privBuf, 32, privBignum)     
            o.EC_KEY_set_private_key(ec_key, privBignum)            
            return o.EC_KEY_dup(ec_key)
        finally:
            o.BN_free(privBignum)
            o.EC_KEY_free(ec_key)




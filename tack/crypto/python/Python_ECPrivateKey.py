# Authors: 
#   Trevor Perrin
#
# See the LICENSE file for legal information regarding use of this file.

import os
from tack.crypto.Digest import Digest
from .cryptomath import numberToBytes, bytesToNumber
from .ecdsa import generator_256, Public_key, Private_key, Point
from .Python_ECPublicKey import Python_ECPublicKey

class Python_ECPrivateKey:

    def __init__(self, rawPrivateKey, rawPublicKey):
        assert(rawPrivateKey is not None and rawPublicKey is not None)
        assert(len(rawPrivateKey)==32 and len(rawPublicKey) == 64)

        self.rawPrivateKey = rawPrivateKey
        self.rawPublicKey  = rawPublicKey

    def sign(self, data):        
        privateKeyNum = bytesToNumber(self.rawPrivateKey)
        hash = Digest.SHA256(data)
        g = generator_256
        n = g.order()
        x = bytesToNumber(self.rawPublicKey[ : 32])
        y = bytesToNumber(self.rawPublicKey[32 : ])        
        pubkey = Public_key(g, Point(g.curve(), x,y))    
        privkey = Private_key(pubkey, privateKeyNum)    

        # Generating random nonce k per FIPS 186-3 B.5.1:
        # (except we use 32 extra bytes instead of 8 before reduction)
        # Random bytes taken from os.urandom as well as HMAC(privkey,hash)
        # REVIEW THIS CAREFULLY!!!  CHANGE AT YOUR PERIL!!!
        
        # 64 random bytes and HMAC(rawPrivateKey,hash) are used as key for an
        # HMAC PRF to generate a 64-byte value which is reduced modulo
        # n to produce the nonce 
        #
        # The use of HMAC(rawPrivateKey,hash) means this construction
        # will be secure even if os.urandom fails, however we include 
        # os.urandom anyways out of an excess of caution 
        randBytes0  = bytearray(os.urandom(64))
        randBytes0 += Digest.HMAC_SHA256(self.rawPrivateKey, hash)
        randBytes  = Digest.HMAC_SHA256(randBytes0, bytearray([1]))
        randBytes += Digest.HMAC_SHA256(randBytes0, bytearray([2]))                       
        c = bytesToNumber(randBytes) 
        k = (c % (n-1))+1                
        hashNum = bytesToNumber(hash)
        sig = privkey.sign(hashNum, k)
        sigBytes = numberToBytes(sig.r, 32) + numberToBytes(sig.s, 32)
        # Double-check the signature before returning
        assert(Python_ECPublicKey(self.rawPublicKey).verify(data, sigBytes))
        return sigBytes        

    def getRawKey(self):
        return self.rawPrivateKey
        

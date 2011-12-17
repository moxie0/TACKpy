from ecdsa import *
from cryptomath import *

################ ECDSA_WRAPPERS ###

import os

def ec256Generate(extraRandBytes=None):
    # ECDSA key generation per FIPS 186-3 B.4.1
    # (except we use 32 extra random bytes instead of 8 before reduction)
    # Random bytes taken from /dev/urandom as well as any extraRandBytes
    # REVIEW THIS CAREFULLY!  CHANGE AT YOUR PERIL!
    randBytes0 = bytearray(os.urandom(64))
    if extraRandBytes:
        randBytes0 += bytearray(extraRandBytes)
    randBytes = HMAC_SHA256(randBytes0, bytearray([1]))
    randBytes+= HMAC_SHA256(randBytes0, bytearray([2]))
    c = bytesToNumber(randBytes) 
    n = generator_256.order()
    d = (c % (n-1))+1        
    privateKey = numberToBytes(d, 32)
    publicKeyPoint = generator_256 * d        
    publicKey = numberToBytes(publicKeyPoint.x(), 32) + \
                numberToBytes(publicKeyPoint.y(), 32)
    return (privateKey, publicKey)

def ecdsa256Sign(privateKey, publicKey, dataToSign):
    privateKeyNum = bytesToNumber(privateKey)
    hash = SHA256(dataToSign)
    g = generator_256
    n = g.order()
    x = bytesToNumber(publicKey[:32])
    y = bytesToNumber(publicKey[32:])        
    pubkey = Public_key(g, Point(g.curve(), x,y))    
    privkey = Private_key(pubkey, privateKeyNum)    

    # Generating random nonce k per FIPS 186-3 B.5.1:
    # (except we use 32 extra bytes instead of 8 before reduction)
    # Random bytes taken from /dev/urandom as well as HMAC(privkey,hash)
    # REVIEW THIS CAREFULLY!!!  CHANGE AT YOUR PERIL!!!
    randBytes0 = bytearray(os.urandom(64))
    randBytes0+= HMAC_SHA256(privateKey, hash)
    randBytes = HMAC_SHA256(randBytes0, bytearray([1]))
    randBytes+= HMAC_SHA256(randBytes0, bytearray([2]))                       
    c = bytesToNumber(randBytes) 
    k = (c % (n-1))+1                
    hashNum = bytesToNumber(hash)
    sig = privkey.sign(hashNum, k)
    assert(pubkey.verifies(hashNum, sig))
    return numberToBytes(sig.r, 32) + numberToBytes(sig.s, 32)

def ecdsa256Verify(publicKey, dataToVerify, signature):
    hashNum = bytesToNumber(SHA256(dataToVerify))
    g = generator_256  
    x = bytesToNumber(publicKey[:32])
    y = bytesToNumber(publicKey[32:])        
    pubkey = Public_key(g, Point(g.curve(), x,y))
    sig = Signature(bytesToNumber(signature[:32]), 
                            bytesToNumber(signature[32:]))
    return pubkey.verifies(hashNum, sig)


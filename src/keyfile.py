from ecdsa_wrappers import *
from rijndael import *
from struct_parser import *
from pem import *

################ KEY FILE ###

import os
#  File format:
#
#  version        1  byte = 0x01
#  iter_count     4 bytes = uint32
#  salt          16 bytes
#  IV            16 bytes         } auth
#    EC privkey  32 bytes  } enc  } auth
#  EC pubkey     64 bytes         } auth
#  HMAC          32 bytes	
# 
#  total		165

def xorbytes(s1, s2):
    return bytearray([a^b for a,b in zip(s1,s2)])

# Uses PBKDF2-HMAC-SHA256 to produce a 32-byte key
def pbkdf2_hmac_sha256(password, salt, iterations):
    m = salt + bytearray([0,0,0,1])
    result = bytearray(32)
    for c in range(iterations):
        m = HMAC_SHA256(bytearray(password, "ascii"), m)
        result = xorbytes(m, result)
    return result

# Uses PBKDF2, then HMAC-SHA256 as PRF to derive independent 32-byte keys
def deriveKeyFileKeys(password, salt, iter_count):
    assert(iter_count>0)
    masterKey = pbkdf2_hmac_sha256(password, salt, iter_count)
    encKey = HMAC_SHA256(masterKey, bytearray([1]))
    authKey = HMAC_SHA256(masterKey, bytearray([2]))
    return (encKey, authKey)

def aes_cbc_decrypt(key, IV, ciphertext):
    cipher = rijndael(key, 16)
    assert(len(ciphertext) % 16 == 0) # no padding
    chainBlock = IV
    plaintext = bytearray() # not efficient, but doesn't matter here
    for c in range(len(ciphertext)//16):
        cipherBlock = ciphertext[c*16 : (c*16)+16]
        plaintext += xorbytes(cipher.decrypt(cipherBlock), chainBlock)
        chainBlock = cipherBlock
    return plaintext

def aes_cbc_encrypt(key, IV, plaintext):
    cipher = rijndael(key, 16)
    assert(len(plaintext) % 16 == 0) # no padding
    chainBlock = IV
    ciphertext = bytearray() # not efficient, but doesn't matter here
    for c in range(len(plaintext)//16):
        plainBlock = plaintext[c*16 : (c*16)+16]
        chainBlock = cipher.encrypt(xorbytes(plainBlock, chainBlock))
        ciphertext += chainBlock
    return ciphertext     

class TACK_KeyFileViewer:
    def __init__(self):
        self.version = 0
        self.iter_count = 0
        self.salt = bytearray(16)
        self.IV = bytearray(16)
        self.ciphertext = bytearray(64)
        self.public_key = bytearray(64)
        self.mac = bytearray(32)
        
    def parse(self, b):
        try:
            b = dePem(b, "TACK KEY")
        except SyntaxError:
            pass        
        p = Parser(b)
        self.version = p.getInt(1)
        if self.version != 1:
            raise SyntaxError("Bad version in Secret File")
        self.iter_count = p.getInt(4)
        self.salt = p.getBytes(16)
        self.IV = p.getBytes(16)
        self.ciphertext = p.getBytes(32)
        self.public_key = p.getBytes(64)
        self.mac = bytearray(p.getBytes(32))
        assert(p.index == len(b)) # did we fully consume byte-array?

    def writeText(self):
        s = \
"""version                = %d
iter_count             = %d
salt                   = 0x%s
IV                     = 0x%s
ciphertext             = 0x%s
public_key             = 0x%s
mac                    = 0x%s\n""" % \
        (self.version, 
        self.iter_count,
        writeBytes(self.salt),
        writeBytes(self.IV),
        writeBytes(self.ciphertext),
        writeBytes(self.public_key),
        writeBytes(self.mac))
        return s        
        
    
class TACK_KeyFile:
    def __init__(self):
        self.version = 0
        self.private_key = bytearray(32)
        self.public_key = bytearray(64)
        self.iter_count = 0
        
    def generate(self, extraRandBytes=None):
        self.version = 1
        self.private_key, self.public_key = ec256Generate(extraRandBytes)
        self.iter_count = 8192

    def sign(self, bytesToSign):
        signature = ecdsa256Sign(self.private_key, self.public_key, bytesToSign)
        return signature

    def parse(self, b, password):
        try:
            b = dePem(b, "TACK KEY")
        except SyntaxError:
            pass                
        p = Parser(b)
        self.version = p.getInt(1)
        if self.version != 1:
            raise SyntaxError("Bad version in Secret File")
        self.iter_count = p.getInt(4)
        salt = p.getBytes(16)
        IV = p.getBytes(16)
        ciphertext = p.getBytes(32)
        self.public_key = p.getBytes(64)
        mac = bytearray(p.getBytes(32))
        assert(p.index == len(b)) # did we fully consume byte-array?

        encKey, authKey = deriveKeyFileKeys(password, salt, self.iter_count)
        macData = IV + ciphertext + self.public_key
        calcMac = HMAC_SHA256(authKey, macData)
        if not constTimeCompare(calcMac, mac):
            return False        
        plaintext = aes_cbc_decrypt(encKey, IV, ciphertext)
        self.private_key = plaintext
        return True
    
    def write(self, password, binary=False):
        salt = bytearray(os.urandom(16))
        IV = bytearray(os.urandom(16))
        encKey, authKey = deriveKeyFileKeys(password, salt, self.iter_count)
        plaintext = self.private_key
        ciphertext = aes_cbc_encrypt(encKey, IV, plaintext)
        macData = IV + ciphertext + self.public_key
        mac = HMAC_SHA256(authKey, macData)        
        w = Writer(165)
        w.add(self.version, 1)
        w.add(self.iter_count, 4)
        w.add(salt, 16)
        w.add(IV, 16)
        w.add(ciphertext, 32)
        w.add(self.public_key, 64)
        w.add(mac, 32)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?
        if not binary:
            b = pem(w.bytes, "TACK KEY")
        else:
            b = w.bytes
        return b


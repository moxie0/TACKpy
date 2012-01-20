from ecdsa_wrappers import *
from rijndael import *
from struct_parser import *
from pem import *
from aes_wrappers import *

################ KEY FILE ###

import os
"""
File format:

  version        1  byte = 0x01
  iter_count     4 bytes = uint32, bigendian
  salt          16 bytes
  IV            16 bytes                } hmac-sha256
    EC privkey  32 bytes  } aes256-cbc  } hmac-sha256
  EC pubkey     64 bytes                } hmac-sha256
  HMAC          32 bytes	

  Total		    165

The AES256-CBC and HMAC-SHA256 steps require independent
32-byte keys (encKey and authKey, respectively).

These keys are derived from a 32-byte masterKey.  The masterKey is
derived from a password via PBKDF2-HMAC-SHA26:

  masterKey = PBKDF2-HMAC-SHA256(password, salt, iter_count)
  encKey = HMAC-SHA256(masterKey, 0x01)
  authKey = HMAC-SHA256(masterKey, 0x02)
"""

def xorbytes(s1, s2):
    return bytearray([a^b for a,b in zip(s1,s2)])

# Uses PBKDF2-HMAC-SHA256 to produce a 32-byte key
def pbkdf2_hmac_sha256(password, salt, iter_count):
    m = salt + bytearray([0,0,0,1])
    result = bytearray(32)
    for c in range(iter_count):
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
  

class TACK_KeyFileViewer:
    def __init__(self):
        self.version = 0
        self.iter_count = 0
        self.salt = bytearray(16)
        self.IV = bytearray(16)
        self.ciphertext = bytearray(64)
        self.public_key = bytearray(64)
        self.mac = bytearray(32)
        
    def parse(self, s):
        b = dePem(s, "TACK SECRET KEY")
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
        assert(p.index == len(b)) # did we fully consume bytearray?

    def writeText(self):
        s = \
"""version        = %d
iter_count     = %d
salt           = 0x%s
IV             = 0x%s
ciphertext     = 0x%s
public_key     = 0x%s
mac            = 0x%s\n""" % \
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
        
    def create(self, extraRandBytes=None):
        self.version = 1
        self.private_key, self.public_key = ec256Generate(extraRandBytes)
        self.iter_count = 8192

    def sign(self, bytesToSign):
        signature = ecdsa256Sign(self.private_key, self.public_key, bytesToSign)
        return signature

    def parsePem(self, s, password):
        b = dePem(s, "TACK SECRET KEY")
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
        assert(p.index == len(b)) # did we fully consume bytearray?

        encKey, authKey = deriveKeyFileKeys(password, salt, self.iter_count)
        macData = IV + ciphertext + self.public_key
        calcMac = HMAC_SHA256(authKey, macData)
        if not constTimeCompare(calcMac, mac):
            return False   
        plaintext = createAES(encKey, IV).decrypt(ciphertext)     
        self.private_key = plaintext
        return True
    
    def writePem(self, password):
        salt = bytearray(os.urandom(16))
        IV = bytearray(os.urandom(16))
        encKey, authKey = deriveKeyFileKeys(password, salt, self.iter_count)
        plaintext = self.private_key
        ciphertext = createAES(encKey, IV).encrypt(plaintext)
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
        assert(w.index == len(w.bytes)) # did we fill entire bytearray?
        b = pem(w.bytes, "TACK SECRET KEY")
        return b

def testKeyFile():
    print("Testing KEY FILE")
    s = """
-----BEGIN TACK SECRET KEY-----
AQAAIAANLO3iLVTKinPS0vjiOWrKlRJs3h3suyLP0LlG4QuO7KCmbgylHWOh/xTl
nUDNyuz7AI+cv7g9xRxTzovH+2B3ymX9NZy5NCTNIDwbTnclV6Oqt/CqQqiQQX/J
aph9H6ECKAUddiSQsFAzVx321FScrXnjOheLQSMkpkhA5C3J+eAbqczO7JITVgUP
RnFe/FSmrtFC6wC5udfQQT5PNfOw
-----END TACK SECRET KEY-----"""
    publicKey = a2b_hex("ca65fd359cb93424cd203c1b4e772557"+
                       "a3aab7f0aa42a890417fc96a987d1fa1"
                       "0228051d762490b05033571df6d4549c"
                       "ad79e33a178b412324a64840e42dc9f9")
    privateKey = a2b_hex("73e6ea5e33e4e591e1e4032bf8300e4c" +
                         "10d4e452506d5c35894625325bcc155e")
    kf = TACK_KeyFile()
    assert(kf.parsePem(s, "asdf"))
    assert(kf.public_key == publicKey)
    assert(kf.private_key == privateKey)
    kf2 = TACK_KeyFile()
    assert(kf2.parsePem(kf.writePem("cdef"), "cdef"))    
    assert(kf.public_key == publicKey)
    assert(kf.private_key == privateKey)
    return 1
# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

from .ecdsa_wrappers import *
from .rijndael import *
from .struct_parser import *
from .pem import *
from .aes_wrappers import *
from .tackid import *

################ KEY FILE ###

import os
"""
File format:

  version        1  byte = 0x01
  iter_count     4 bytes = uint32, bigendian
  salt          16 bytes
  EC privkey    32 bytes  } aes256-cbc(IV=0)  } hmac-sha256
  EC pubkey     64 bytes                      } hmac-sha256
  HMAC          32 bytes	

  Total		    149

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
        self.ciphertext = bytearray(64)
        self.public_key = bytearray(64)
        self.mac = bytearray(32)
        
    def parse(self, s):
        b = dePem(s, "TACK PRIVATE KEY")
        p = Parser(b)
        self.version = p.getInt(1)
        if self.version != 1:
            raise SyntaxError("Bad version in Secret File")
        self.iter_count = p.getInt(4)
        self.salt = p.getBytes(16)
        self.ciphertext = p.getBytes(32)
        self.public_key = p.getBytes(64)
        self.mac = bytearray(p.getBytes(32))
        if p.index != len(b):
            raise SyntaxError("Excess bytes in TACK Key File")

    def writeText(self):
        return "TACK ID        = %s\n" % makeTACKID(self.public_key)
    
class TACK_KeyFile:
    length = 149 # length of keyfile in bytes
        
    def __init__(self):
        self.version = 0
        self.private_key = bytearray(32)
        self.public_key = bytearray(64)
        self.iter_count = 0
        
    def create(self):
        self.version = 1
        self.private_key, self.public_key = ec256Generate()
        self.iter_count = 8192

    def sign(self, bytesToSign):
        signature = ecdsa256Sign(self.private_key, self.public_key, bytesToSign)
        return signature

    def parsePem(self, s, password):
        b = dePem(s, "TACK PRIVATE KEY")
        p = Parser(b)
        self.version = p.getInt(1)
        if self.version != 1:
            raise SyntaxError("Bad version in Secret File")
        self.iter_count = p.getInt(4)
        salt = p.getBytes(16)
        ciphertext = p.getBytes(32)
        self.public_key = p.getBytes(64)
        mac = bytearray(p.getBytes(32))
        if p.index != len(b):
            raise SyntaxError("Excess bytes in TACK Key File")

        encKey, authKey = deriveKeyFileKeys(password, salt, self.iter_count)
        macData = ciphertext + self.public_key
        calcMac = HMAC_SHA256(authKey, macData)
        if not constTimeCompare(calcMac, mac):
            return False   
        plaintext = createAES(encKey, bytearray(16)).decrypt(ciphertext)     
        self.private_key = plaintext
        return True

    def writeText(self):
        s = \
"""TACK ID        = %s\n""" % makeTACKID(self.public_key)
        return s  

    def writePem(self, password):
        salt = bytearray(os.urandom(16))
        IV = bytearray(os.urandom(16))
        encKey, authKey = deriveKeyFileKeys(password, salt, self.iter_count)
        plaintext = self.private_key
        ciphertext = createAES(encKey, bytearray(16)).encrypt(plaintext)
        macData = ciphertext + self.public_key
        mac = HMAC_SHA256(authKey, macData)        
        w = Writer(TACK_KeyFile.length)
        w.add(self.version, 1)
        w.add(self.iter_count, 4)
        w.add(salt, 16)
        w.add(ciphertext, 32)
        w.add(self.public_key, 64)
        w.add(mac, 32)
        assert(w.index == len(w.bytes)) # did we fill entire bytearray?
        b = pem(w.bytes, "TACK PRIVATE KEY")
        return b

def testKeyFile():
    print("Testing KEY FILE")
    s = """
    -----BEGIN TACK PRIVATE KEY-----
    AQAAIAAjOxiOdpiMo5qWidXwBTqJHxW5X1zRDBOA4ldqqFuKOSh6JJdrbXk1WsMN
    X/gyaVuHMBhC/g/rjtu/EnmIHoUuT9348iXeeROaLVRPdNqwr+5KEfjtTY7uXA6Q
    mhRUn+XmDePKRucRHYkcQaFPnzglrQ120Dh6aXD4PbtJMWajJtzTMvtEo9pNZhoM
    QTNZNoM=
    -----END TACK PRIVATE KEY-----"""
    publicKey = a2b_hex("87301842fe0feb8edbbf1279881e852e"
                        "4fddf8f225de79139a2d544f74dab0af"
                        "ee4a11f8ed4d8eee5c0e909a14549fe5"
                         "e60de3ca46e7111d891c41a14f9f3825")
    privateKey = a2b_hex("fc815de8b1de13a436e9cd69742cbf2c"
                         "d4c1c9bb33e023401d9291cf2781b754")
    kf = TACK_KeyFile()
    assert(kf.parsePem(s, "asdf"))
    assert(kf.public_key == publicKey)
    assert(kf.private_key == privateKey)
    kf2 = TACK_KeyFile()
    assert(kf2.parsePem(kf.writePem("cdef"), "cdef"))    
    assert(kf.public_key == publicKey)
    assert(kf.private_key == privateKey)
    kf3 = TACK_KeyFile()
    kf3.create()
    kf4 = TACK_KeyFile()
    assert(kf4.parsePem(kf3.writePem("123"), "123"))
    assert(kf3.public_key == kf4.public_key)
    return 1

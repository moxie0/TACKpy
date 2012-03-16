# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

from .constants import *
from .struct_parser import *
from .time_funcs import *
from .misc import *
from .pem import *
from .ecdsa_wrappers import *
from .tackid import *

################ TACK STRUCTURES ###

import os # for os.urandom
        
class TACK_Key:
    length = 65 # length of TACK_Key in bytes
    
    def __init__(self):
        """Create an uninitialized TACK_Key.  
        
        Use create() or parse() to populate."""
        self.type = 0 # integer from TACK_Key_Type
        self.public_key = bytearray(64) # EC public key using NIST-P256
    
    def create(self, public_key):
        """Initialize a TACK_Key, based on the input key 32-byte bytearray."""
        self.type = TACK_Key_Type.v1
        assert(len(public_key) == 64)
        self.public_key = public_key

    def getTACKID(self):
        return hashToTACKID(SHA256(self.write())[:15])    
            
    def parse(self, b):
        """Parse a bytearray of 73 bytes to populate this TACK_Key.
        
        Raise a SyntaxError if input is malformed.
        """
        p = Parser(b)
        self.type = p.getInt(1)
        if self.type != TACK_Key_Type.v1:
            raise SyntaxError("Bad key.type")
        self.public_key = p.getBytes(64)
        if p.index != len(b):
            raise SyntaxError("Excess bytes in TACK_Key")        
        
    def write(self):        
        """Return a 65-byte bytearray encoding of this TACK_Key."""
        assert(self.type == TACK_Key_Type.v1)        
        w = Writer(TACK_Key.length)
        w.add(self.type, 1)
        w.add(self.public_key, 64)
        assert(w.index == len(w.bytes)) # did we fill entire bytearray?            
        return w.bytes  

    def writeText(self):
        """Return a readable string describing this TACK_Key.
        
        Used by the "TACK view" command to display TACK objects."""
        assert(self.type == TACK_Key_Type.v1)
        s = \
"""TACK ID        = %s\n""" % \
(self.getTACKID())
        return s
        
           
class TACK_Sig:
    length = 103 # length of TACK_Sig in bytes
        
    def __init__(self):
        """Create an uninitialized TACK_Sig.  
        
        Use create() or parse() to populate."""        
        self.type = 0 # 8-bit value from TACK_Key_Type (v1)
        self.min_generation = 0 # 8-bit integer
        self.generation = 0 # 8-bit integer               
        self.expiration = 0 # 32-bit unsigned integer encoding POSIX time
        self.target_sha256 = bytearray(32) # 32-byte SHA256 result
        self.signature = bytearray(64) # ECDSA signature using NIST-P256
        
    def create(self, type, min_generation, generation, expiration,
                target_sha256, key, signFunc):
        """Initialize a TACK_Sig.

        The input args are mostly used to set TACK_Sig fields directly.
        However, the last two args contain a TACK_Key object and an ECDSA
        signing function, which are used to populate the "signature" value. 
        
        The signing function takes an input bytearray, and returns a
        64-byte signature of the bytearray based on ECDSA-NIST-P256-SHA256.
        
        To calculate the signing function input, the TACK_Key is written to a 
        73-byte bytearray, then the 38 bytes of TACK_Sig fields prior to the 
        "signature" are appended, yielding a 111-byte bytearray.
        """
        assert(type == TACK_Sig_Type.v1)
        assert(min_generation >= 0 and min_generation <= 255)                
        assert(generation >= 0 and generation <= 255 and 
                generation >= min_generation)
        assert(expiration >=0 and expiration <= 2**32-1)
        assert(len(target_sha256) == 32)                
        self.type = type
        self.min_generation = min_generation
        self.generation = generation                
        self.expiration = expiration        
        self.target_sha256 = target_sha256
        self.signature = signFunc(key.write() + self.write()[:-64])
    
    def parse(self, b):
        """Parse a bytearray of 102 bytes to populate this TACK_Sig.
        
        Raise a SyntaxError if input is malformed.
        """        
        p = Parser(b)
        self.type = p.getInt(1)
        if self.type != TACK_Sig_Type.v1:
            raise SyntaxError("Bad sig.type")
        self.min_generation = p.getInt(1)
        self.generation = p.getInt(1)            
        self.expiration = p.getInt(4)
        self.target_sha256 = p.getBytes(32)
        self.signature = p.getBytes(64)
        if p.index != len(b):
            raise SyntaxError("Excess bytes in TACK_Sig")
        
    def write(self):
        """Return a 102-byte bytearray encoding of this TACK_Sig."""        
        assert(self.type == TACK_Sig_Type.v1)
        w = Writer(TACK_Sig.length)
        w.add(self.type, 1)
        w.add(self.min_generation, 1)
        w.add(self.generation, 1)
        w.add(self.expiration, 4)
        w.add(self.target_sha256, 32)
        w.add(self.signature, 64)
        assert(w.index == len(w.bytes)) # did we fill entire bytearray?
        return w.bytes

    def writeText(self):
        """Return a readable string describing this TACK_Sig.
        
        Used by the "TACK view" command to display TACK objects."""        
        assert(self.type == TACK_Sig_Type.v1)
        s = \
"""min_generation = %d
generation     = %d
expiration     = %s
target_sha256  = 0x%s\n""" % \
(self.min_generation,
self.generation,
posixTimeToStr(self.expiration*60),
writeBytes(self.target_sha256))
        return s

class TACK:
    length =  TACK_Key.length + TACK_Sig.length  # 168 bytes
    
    def __init__(self):
        """Create an uninitialized TACK.  
        
        Use create() or parsePem() to populate."""        
        self.key = None # class TACK_Key
        self.sig = None # class TACK_Sig

    def create(self, keyFile, sigType, min_generation, generation, 
                expiration, target_sha256):
        """Initialize a TACK.

        The input args are passed to TACK_Key.create() or TACK_Sig.create()
        """        
        self.key = TACK_Key()
        self.key.create(keyFile.public_key)
        self.update(keyFile, sigType, min_generation, generation, 
                    expiration, target_sha256)
                
    def update(self, keyFile, sigType, min_generation, generation, 
                expiration, target_sha256):
        """Create a new TACK_Sig for the TACK.

        The existing TACK_Sig is replaced.  The existing TACK_Key is 
        unmodified.        """                        
        self.sig = TACK_Sig()
        self.sig.create(sigType, min_generation, generation,  
                        expiration, target_sha256, 
                        self.key, keyFile.sign)

    def getTACKID(self):
        return self.key.getTACKID()

    def verifySignature(self):
        bytesToVerify = self.key.write() + self.sig.write()[:-64]
        return ecdsa256Verify(self.key.public_key, bytesToVerify, 
                                self.sig.signature)  

    def parsePem(self, s):
        """Parse a string containing a PEM file for a TACK.
        
        Raise a SyntaxError if input is malformed, including signature
        validation failure.
        """        
        b = dePem(s, "TACK")
        if len(b) != TACK.length:
            raise SyntaxError("TACK is the wrong size")
        self.parse(b)
        
    def parse(self, b):
        """Parse a bytearray containing a TACK.
        
        Raise a SyntaxError if input is malformed, including signature
        validation failure.
        """        
        self.key = TACK_Key()
        self.sig = TACK_Sig()
        self.key.parse(b[ : TACK_Key.length])
        b = b[TACK_Key.length : ]
        self.sig.parse(b[ : TACK_Sig.length])
        b = b[TACK_Sig.length : ]
        p = Parser(b)
        if not self.verifySignature():
            raise SyntaxError("Signature verification failure")
        if p.index != len(b):
            raise SyntaxError("Excess bytes in TACK")
        

    def writePem(self):
        """Return a string containing a PEM file for the TACK."""        
        return pem(self.write(), "TACK")
        
    def write(self):
        """Return a bytearray containing the TACK."""
        w = Writer(TACK.length)
        w.add(self.key.write(), TACK_Key.length) 
        w.add(self.sig.write(), TACK_Sig.length)
        return w.bytes

    def writeText(self):
        """Return a readable string describing this TACK.
        
        Used by the "TACK view" command to display TACK objects."""        
        s =\
"""%s%s""" % \
            (self.key.writeText(), self.sig.writeText())
        return s   
        
class TACK_Break_Sig:
    length = 64 + TACK_Key.length  # totals 129
    
    def __init__(self):
        """Create an uninitialized TACK_Break_Sig.  
        
        Use create() or parsePem() to populate."""        
        self.key = None # TACK_Key
        self.signature = bytearray(64) # ECDSA signature on TACK_Key
        
    def create(self, key, signature):
        """Initialize a TACK_Break_Sig with a TACK_Key and 64-byte bytearray.
        """        
        assert(len(signature) == 64)
        self.key = key
        self.signature = signature
        
    def getTACKID(self):
        return self.key.getTACKID()
        
    def verifySignature(self):
        bytesToVerify = self.key.write()
        return ecdsa256Verify(self.key.public_key, bytesToVerify, 
                                self.signature)         

    def parsePem(self, s):
        """Parse a string containing a PEM file for a TACK_Break_Sig.
        
        Raise a SyntaxError if input is malformed.
        """        
        b = dePem(s, "TACK BREAK SIG")
        if len(b) != TACK_Break_Sig.length:
            raise SyntaxError("Break Sig is the wrong size")        
        self.parse(b)

    def parse(self, b):
        """Parse a bytearray containing a TACK_Break_Sig.
        
        Raise a SyntaxError if input is malformed, including signature
        validation failure.
        """        
        p = Parser(b)
        self.key = TACK_Key()
        self.key.parse(b[ : TACK_Key.length])
        b = b[TACK_Key.length : ]  
        p = Parser(b)      
        self.signature = p.getBytes(64)
        if not self.verifySignature():
            raise SyntaxError("Signature verification failure")        
        if p.index != len(b):
            raise SyntaxError("Excess bytes in TACK_Break_Sig")

    def write(self):
        """Return a bytearray containing the TACK_Break_Sig."""
        w = Writer(TACK_Break_Sig.length)
        w.add(self.key.write(), TACK_Key.length)
        w.add(self.signature, 64)
        assert(w.index == len(w.bytes)) # did we fill entire bytearray?
        return w.bytes        
                
    def writePem(self):
        """Return a string containing a PEM file for the TACK_Break_Sig."""
        return pem(self.write(), "TACK BREAK SIG")

    def writeText(self):
        """Return a readable string describing this TACK_Break_Sig.
        
        Used by the "TACK view" command to display TACK objects."""        
        #s = self.key.writeText()
        s = "Breaks TACK ID = %s\n" % self.key.getTACKID()
        return s


    @staticmethod
    def parsePemList(s):
        """Parse a string containing a sequence of PEM Break Sigs.

        Raise a SyntaxError if input is malformed.
        """        
        breakSigs = []
        bList = dePemList(s, "TACK BREAK SIG")
        for b in bList:
            breakSig = TACK_Break_Sig()
            breakSig.parse(b)
            breakSigs.append(breakSig)
        return breakSigs 


class TACK_Extension:

    def __init__(self):
        self.tack = None
        self.break_sigs = None # aka []
        
    def create(self, tack=None, break_sigs=None):
        self.tack = tack
        self.break_sigs = break_sigs        
    
    def isEmpty(self):
        return (not self.tack and not self.break_sigs)

    def parse(self, b, allowNewVersions=False):
        self.tack = None
        self.break_sigs = []         
        p = Parser(b)

        tackLen = p.getInt(2)
        if tackLen > 1024:
            raise SyntaxError("TACK too large")
        if tackLen:
            b2 = p.getBytes(tackLen)
            if b2[0] != TACK_Key_Type.v1:
                if not allowNewVersions:
                    raise SyntaxError("Only supports v1 TACKs")
            else:
                self.tack = TACK()
                self.tack.parse(b2)

        sigsLen = p.getInt(2)
        if sigsLen > 2048:
            raise SyntaxError("break_sigs too large")
        if sigsLen:
            b2 = p.getBytes(sigsLen)
            while b2:
                if b2[0] != TACK_Key_Type.v1:
                    if not allowNewVersions:
                        raise SyntaxError("Only supports v1 break sigs")
                    break
                breakSig = TACK_Break_Sig()
                breakSig.parse(b2[:TACK_Break_Sig.length])
                self.break_sigs.append(breakSig)
                b2 = b2[TACK_Break_Sig.length:]
        if p.index != len(b):
            raise SyntaxError("Excess bytes in TACK_Extension")

    def write(self):
        length = 0
        if self.tack:
            length += TACK.length
        if self.break_sigs:
            length += len(self.break_sigs) * TACK_Break_Sig.length
        w = Writer(length+4)
        if self.tack:
            w.add(TACK.length, 2)
            w.add(self.tack.write(), TACK.length)
        else:
            w.add(0, 2)
        if self.break_sigs:
            w.add(len(self.break_sigs) * TACK_Break_Sig.length, 2)
            for break_sig in self.break_sigs:
                w.add(break_sig.write(), TACK_Break_Sig.length)
        else:
            w.add(0, 2)
        assert(w.index == len(w.bytes)) # did we fill entire bytearray?
        return w.bytes
    
    def writeText(self):
        return writeTextTACKStructures(self.tack, self.break_sigs)
        
            
    
def writeTextTACKStructures(tack, breakSigs, tackidOnly=False):        
    s = ""
    if tack:
        if not tackidOnly:
            s += tack.writeText()
        else:
            s += tack.getTACKID()+"\n"
    if breakSigs:
        for breakSig in breakSigs:
            s += breakSig.writeText()
    return s

def testTACKStructures():
    print("Testing TACK STRUCTURES")
    s = """
-----BEGIN TACK-----
AR3jPQCkF1ud7U9hb44zpFuRLz6EKE22hwQRkQFEdxT/YUd5Qi7FYCtVk1+P1nh+
/ZPihRFAXJH0WkN4L5bSS7wBAAACQnQFvz5Foz1gTLBokQZWIokmalgb+AkeB8Zp
58j2QptdIOYCTri1KsSYPuRK4LSannEvgQxfG58c84RxNu69VS6ihZVNlkx8/zGU
C6ag+gdToKLmPJDQIXb0cdO04CbTu2Hc
-----END TACK-----"""
    t = TACK()
    t.parsePem(s)
    assert(t.key.type == TACK_Key_Type.v1)
    assert(t.key.public_key == a2b_hex(
"1de33d00a4175b9ded4f616f8e33a45b"
"912f3e84284db68704119101447714ff"
"614779422ec5602b55935f8fd6787efd"
"93e28511405c91f45a43782f96d24bbc"))
    assert(t.sig.type == TACK_Sig_Type.v1)
    assert(posixTimeToStr(t.sig.expiration*60) == "2042-01-29T01:09Z")
    assert(t.sig.generation == 0)
    assert(t.sig.target_sha256 == a2b_hex("bf3e45a33d604cb0689106562289266a"
                   "581bf8091e07c669e7c8f6429b5d20e6"))
    assert(t.sig.signature == a2b_hex("024eb8b52ac4983ee44ae0b49a9e712f"
                   "810c5f1b9f1cf3847136eebd552ea285"
                   "954d964c7cff31940ba6a0fa0753a0a2"
                   "e63c90d02176f471d3b4e026d3bb61dc"))
    s = """
-----BEGIN TACK BREAK SIG-----
AR3jPQCkF1ud7U9hb44zpFuRLz6EKE22hwQRkQFEdxT/YUd5Qi7FYCtVk1+P1nh+
/ZPihRFAXJH0WkN4L5bSS7wLSfGPO7ezR9GJtpI2pFfaGFwYRy2jpbjg4T+O5SAu
FwFGRqeNl/uT+iTRYJH+GU0hHkA+v6Rm0oBt2COSvP5E
-----END TACK BREAK SIG-----"""
    tbs = TACK_Break_Sig()
    tbs.parsePem(s)
    assert(tbs.key.type == TACK_Key_Type.v1)
    assert(tbs.getTACKID() == "BCX9R.6IYW3.8TN4D.5G9JJ.I18GY")
    assert(tbs.signature == a2b_hex(
"0b49f18f3bb7b347d189b69236a457da"
"185c18472da3a5b8e0e13f8ee5202e17"
"014646a78d97fb93fa24d16091fe194d"
"211e403ebfa466d2806dd82392bcfe44"))

    s = """                       
Created by TACK.py 0.9.6
Created at 2012-03-15T20:42:21Z
-----BEGIN TACK BREAK SIG-----
AR3jPQCkF1ud7U9hb44zpFuRLz6EKE22hwQRkQFEdxT/YUd5Qi7FYCtVk1+P1nh+
/ZPihRFAXJH0WkN4L5bSS7wLSfGPO7ezR9GJtpI2pFfaGFwYRy2jpbjg4T+O5SAu
FwFGRqeNl/uT+iTRYJH+GU0hHkA+v6Rm0oBt2COSvP5E
-----END TACK BREAK SIG-----
Created by TACK.py 0.9.6
Created at 2012-03-15T20:42:22Z
-----BEGIN TACK BREAK SIG-----
ATBZ2H0kKqfIK0s0lFLr5zogOTLHpkXawY9cGd5W19IkKofKjPLl6yHGAuxFIgF3
K3SpVgeBp0R2gpBKuEnLxH1DfR2lg+gjycXKc0JXoAR3TeOG3Aig6Y9ziVHvikHD
5jlRD867NH5U3zE/xHka02Lhd3zRao0sEPsy6WCuPJze
-----END TACK BREAK SIG-----
"""
    tbsList = TACK_Break_Sig.parsePemList(s)
    assert(tbsList[0].getTACKID()  == "BCX9R.6IYW3.8TN4D.5G9JJ.I18GY")
    assert(tbsList[1].getTACKID()  == "BUDHM.4Q6XU.74GEU.ISNA9.KE6LN")
    assert(len(tbsList) == 2)
    return 1
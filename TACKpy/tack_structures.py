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
        
class TACK:
    length =  166
    
    def __init__(self):
        """Create an uninitialized TACK.  
        
        Use create() or parsePem() to populate.""" 
        self.public_key = bytearray(64) # EC public key using NIST-P256
        self.min_generation = 0 # 8-bit integer
        self.generation = 0 # 8-bit integer               
        self.expiration = 0 # 32-bit unsigned integer encoding POSIX time
        self.target_hash = bytearray(32) # 32-byte SHA256 result
        self.signature = bytearray(64) # ECDSA signature using NIST-P256

    def create(self, public_key, min_generation, generation, 
                expiration, target_hash, signFunc=ecdsa256Sign):
        """Initialize a TACK.
        """        
        assert(len(public_key) == 64)        
        self.public_key = public_key       
        self.sign(min_generation, generation, expiration, target_hash, 
                    signFunc)
                
    def sign(self, min_generation, generation, 
                expiration, target_hash, signFunc=ecdsa256Sign):
        """Create a new TACK sig for the TACK.

        The existing TACK sig is replaced.  The existing TACK_Key is 
        unmodified.
        """
        assert(min_generation >= 0 and min_generation <= 255)                
        assert(generation >= 0 and generation <= 255 and 
                generation >= min_generation)
        assert(expiration >=0 and expiration <= 2**32-1)
        assert(len(target_hash) == 32)                
        self.min_generation = min_generation
        self.generation = generation                
        self.expiration = expiration        
        self.target_hash = target_hash
        self.signature = signFunc(self.getToBeSigned()) 
        
    def getTACKID(self):
        return makeTACKID(self.public_key)
        
    def getToBeSigned(self):
        return bytearray("tack_sig", "ascii") + self.write()[:-64]

    def verifySignature(self, verifyFunc):
        bytesToVerify = self.getToBeSigned()
        return verifyFunc(self.public_key, bytesToVerify, self.signature)  

    def parsePem(self, s, verifyFunc=ecdsa256Verify):
        """Parse a string containing a PEM file for a TACK.
        
        Raise a SyntaxError if input is malformed, including signature
        validation failure.
        """        
        b = dePem(s, "TACK")
        if len(b) != TACK.length:
            raise SyntaxError("TACK is the wrong size")
        self.parse(b, verifyFunc)
        
    def parse(self, b, verifyFunc=ecdsa256Verify):
        """Parse a bytearray containing a TACK.
        
        Raise a SyntaxError if input is malformed, including signature
        validation failure.
        """        
        p = Parser(b)      
        self.public_key = p.getBytes(64)          
        self.min_generation = p.getInt(1)
        self.generation = p.getInt(1)            
        self.expiration = p.getInt(4)
        self.target_hash = p.getBytes(32)
        self.signature = p.getBytes(64)
                
        if not self.verifySignature(verifyFunc):
            raise SyntaxError("Signature verification failure")
        if p.index != len(b):
            raise SyntaxError("Excess bytes in TACK")

    def writePem(self):
        """Return a string containing a PEM file for the TACK."""        
        return pem(self.write(), "TACK")
        
    def write(self):
        """Return a bytearray containing the TACK."""
        w = Writer(TACK.length)
        w.add(self.public_key, 64)
        w.add(self.min_generation, 1)
        w.add(self.generation, 1)
        w.add(self.expiration, 4)
        w.add(self.target_hash, 32)
        w.add(self.signature, 64)
        return w.bytes

    def writeText(self):
        """Return a readable string describing this TACK.
        
        Used by the "TACK view" command to display TACK objects."""        
        s =\
"""TACK ID        = %s
min_generation = %d
generation     = %d
expiration     = %s
target_hash    = %s\n""" % \
(self.getTACKID(),
self.min_generation,
self.generation,
posixTimeToStr(self.expiration*60),
writeBytes(self.target_hash))
        return s   
        
class TACK_Break_Sig:
    length = 128
    
    def __init__(self):
        """Create an uninitialized TACK_Break_Sig.  
        
        Use create() or parsePem() to populate."""        
        self.public_key = bytearray(64)
        self.signature = bytearray(64) # ECDSA signature on TACK_Key
        
    def create(self, public_key, signFunc):
        """Initialize a TACK_Break_Sig with a TACK_Key and 64-byte bytearray.
        """        
        assert(len(public_key) == 64)
        self.public_key = public_key
        self.signature = signFunc(bytearray("tack_break_sig", "ascii"))
        
    def getTACKID(self):
        return makeTACKID(self.public_key)
        
    def verifySignature(self, verifyFunc):
        return verifyFunc(self.public_key, bytearray("tack_break_sig", "ascii"), 
                            self.signature)         

    def parsePem(self, s, verifyFunc=ecdsa256Verify):
        """Parse a string containing a PEM file for a TACK_Break_Sig.
        
        Raise a SyntaxError if input is malformed.
        """        
        b = dePem(s, "TACK BREAK SIG")
        if len(b) != TACK_Break_Sig.length:
            raise SyntaxError("Break Sig is the wrong size")        
        self.parse(b, verifyFunc)

    def parse(self, b, verifyFunc=ecdsa256Verify):
        """Parse a bytearray containing a TACK_Break_Sig.
        
        Raise a SyntaxError if input is malformed, including signature
        validation failure.
        """
        p = Parser(b)      
        self.public_key = p.getBytes(64)          
        self.signature = p.getBytes(64)
        if not self.verifySignature(verifyFunc):
            raise SyntaxError("Signature verification failure")        
        if p.index != len(b):
            raise SyntaxError("Excess bytes in TACK_Break_Sig")

    def write(self):
        """Return a bytearray containing the TACK_Break_Sig."""
        w = Writer(TACK_Break_Sig.length)
        w.add(self.public_key, 64)
        w.add(self.signature, 64)
        assert(w.index == len(w.bytes)) # did we fill entire bytearray?
        return w.bytes        
                
    def writePem(self):
        """Return a string containing a PEM file for the TACK_Break_Sig."""
        return pem(self.write(), "TACK BREAK SIG")

    def writeText(self):
        """Return a readable string describing this TACK_Break_Sig.
        
        Used by the "TACK view" command to display TACK objects."""        
        s = "Breaks TACK ID = %s\n" % makeTACKID(self.public_key)
        return s

    @staticmethod
    def parsePemList(s, verifyFunc=ecdsa256Verify):
        """Parse a string containing a sequence of PEM Break Sigs.

        Raise a SyntaxError if input is malformed.
        """        
        breakSigs = []
        bList = dePemList(s, "TACK BREAK SIG")
        for b in bList:
            breakSig = TACK_Break_Sig()
            breakSig.parse(b, verifyFunc)
            breakSigs.append(breakSig)
        return breakSigs 


class TACK_Extension:

    def __init__(self):
        self.tack = None
        self.break_sigs = []
        self.pin_activation = TACK_Activation.disabled      
        
    def create(self, tack, break_sigs, pin_activation):
        self.tack = tack
        self.break_sigs = break_sigs
        self.pin_activation = pin_activation
    
    def isEmpty(self):
        return (not self.tack and not self.break_sigs)

    def parse(self, b, verifyFunc=ecdsa256Verify):
        p = Parser(b)
        tackLen = p.getInt(1)
        if tackLen != TACK.length:
            raise SyntaxError("TACK wrong size")
        else:
            b2 = p.getBytes(tackLen)
            self.tack = TACK()
            self.tack.parse(b2, verifyFunc)

        sigsLen = p.getInt(2)
        if sigsLen >1024:
            raise SyntaxError("break_sigs too large")
        elif sigsLen % TACK_Break_Sig.length != 0:
            raise SyntaxError("break sigs wrong size")
        else:
            self.break_sigs = []
            b2 = p.getBytes(sigsLen)
            while b2:
                breakSig = TACK_Break_Sig()
                breakSig.parse(b2[:TACK_Break_Sig.length], verifyFunc)
                self.break_sigs.append(breakSig)
                b2 = b2[TACK_Break_Sig.length:]
        self.pin_activation = p.getInt(1)
        if self.pin_activation not in TACK_Activation.all:
            raise SyntaxError("Bad pin_activation value")
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
            w.add(TACK.length, 1)
            w.add(self.tack.write(), TACK.length)
        else:
            w.add(0, 1)
        if self.break_sigs:
            w.add(len(self.break_sigs) * TACK_Break_Sig.length, 2)
            for break_sig in self.break_sigs:
                w.add(break_sig.write(), TACK_Break_Sig.length)
        else:
            w.add(0, 2)
        w.add(self.pin_activation, 1)
        assert(w.index == len(w.bytes)) # did we fill entire bytearray?
        return w.bytes
    
    def writeText(self):
        return writeTextTACKStructures(self.tack, self.break_sigs, 
                                    self.pin_activation)

    
def writeTextTACKStructures(tack, breakSigs, pin_activation, 
                                tackidOnly=False):        
    s = ""
    if tack:
        if not tackidOnly:
            s += tack.writeText()
        else:
            s += tack.getTACKID()+"\n"
    if breakSigs:
        for breakSig in breakSigs:
            s += breakSig.writeText()
    s += "pin_activation = %s\n" % \
        TACK_Activation.strings[pin_activation]
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
    assert(t.sig.target_hash == a2b_hex("bf3e45a33d604cb0689106562289266a"
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
    #print tbs.getTACKID()
    assert(tbs.getTACKID() == "bcx9r.6iyw3.8tn4d.5g9jj.i18gy")
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
    #print tbsList[0].getTACKID()
    #print tbsList[1].getTACKID()    
    assert(tbsList[0].getTACKID()  == "bcx9r.6iyw3.8tn4d.5g9jj.i18gy")
    assert(tbsList[1].getTACKID()  == "budhm.4q6xu.74geu.isna9.ke6Ln")
    assert(len(tbsList) == 2)
    return 1
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
    length = 73 # length of TACK_Key in bytes
    
    def __init__(self):
        """Create an uninitialized TACK_Key.  
        
        Use create() or parse() to populate."""
        self.type = 0 # integer from TACK_Key_Type
        self.public_key = bytearray(64) # EC public key using NIST-P256
        self.nonce = bytearray(8)
    
    def create(self, public_key):
        """Initialize a TACK_Key, based on the input key 32-byte bytearray.
        
        The nonce is randomized to distinguish this from other TACK_Keys based
        on the same public_key."""
        self.type = TACK_Key_Type.v1
        assert(len(public_key) == 64)
        self.public_key = public_key
        self.nonce = os.urandom(8)

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
        self.nonce = p.getBytes(8)
        if p.index != len(b):
            raise SyntaxError("Excess bytes in TACK_Key")        
        
    def write(self):        
        """Return a 73-byte bytearray encoding of this TACK_Key."""
        assert(self.type == TACK_Key_Type.v1)        
        w = Writer(TACK_Key.length)
        w.add(self.type, 1)
        w.add(self.public_key, 64)
        w.add(self.nonce, 8)  
        assert(w.index == len(w.bytes)) # did we fill entire bytearray?            
        return w.bytes  

    def writeText(self):
        """Return a readable string describing this TACK_Key.
        
        Used by the "TACK view" command to display TACK objects."""
        assert(self.type == TACK_Key_Type.v1)
        s = \
"""TACK ID        = %s
public_key     = 0x%s\n""" % \
(self.getTACKID(), 
writeBytes(self.public_key))
        return s
        
           
class TACK_Sig:
    length = 102 # length of TACK_Sig in bytes
        
    def __init__(self):
        """Create an uninitialized TACK_Sig.  
        
        Use create() or parse() to populate."""        
        self.type = 0 # 8-bit value from TACK_Key_Type (v1_cert or v1_key)
        self.expiration = 0 # 32-bit unsigned integer encoding POSIX time
        self.generation = 0 # 8-bit integer               
        self.target_sha256 = bytearray(32) # 32-byte SHA256 result
        self.signature = bytearray(64) # ECDSA signature using NIST-P256
        
    def create(self, type, expiration, generation,
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
        assert(type == TACK_Sig_Type.v1_cert or type == TACK_Sig_Type.v1_key)
        assert(expiration >=0 and expiration <= 2**32-1)
        assert(generation >= 0 and generation <= 255)
        assert(len(target_sha256) == 32)                
        self.type = type
        self.expiration = expiration
        self.generation = generation                
        self.target_sha256 = target_sha256
        self.signature = signFunc(key.write() + self.write()[:-64])
    
    def parse(self, b):
        """Parse a bytearray of 102 bytes to populate this TACK_Sig.
        
        Raise a SyntaxError if input is malformed.
        """        
        p = Parser(b)
        self.type = p.getInt(1)
        if self.type not in TACK_Sig_Type.all:
            raise SyntaxError("Bad sig.type")
        self.expiration = p.getInt(4)
        self.generation = p.getInt(1)            
        self.target_sha256 = p.getBytes(32)
        self.signature = p.getBytes(64)
        if p.index != len(b):
            raise SyntaxError("Excess bytes in TACK_Sig")
        
    def write(self):
        """Return a 102-byte bytearray encoding of this TACK_Sig."""        
        assert(self.type in TACK_Sig_Type.all)
        w = Writer(TACK_Sig.length)
        w.add(self.type, 1)
        w.add(self.expiration, 4)
        w.add(self.generation, 1)
        w.add(self.target_sha256, 32)
        w.add(self.signature, 64)
        assert(w.index == len(w.bytes)) # did we fill entire bytearray?
        return w.bytes

    def writeText(self):
        """Return a readable string describing this TACK_Sig.
        
        Used by the "TACK view" command to display TACK objects."""        
        assert(self.type in TACK_Sig_Type.all)
        s = \
"""sig.type       = %s
expiration     = %s
generation     = %d
target_sha256  = 0x%s\n""" % \
(TACK_Sig_Type.strings[self.type], 
posixTimeToStr(self.expiration*60),
self.generation,
writeBytes(self.target_sha256))
        return s

class TACK:
    length = 4 + TACK_Key.length + TACK_Sig.length  # 179 bytes
    
    def __init__(self):
        """Create an uninitialized TACK.  
        
        Use create() or parsePem() to populate."""        
        self.key = None # class TACK_Key
        self.sig = None # class TACK_Sig
        self.duration = 0 # 32-bit unsigned integer, counting minutes

    def create(self, keyFile, sigType, expiration, \
                generation, target_sha256, duration):
        """Initialize a TACK.

        The input args are passed to TACK_Key.create() or TACK_Sig.create(),
        except for duration which is applied directly to self.duration.
        """        
        self.key = TACK_Key()
        self.key.create(keyFile.public_key)
        self.update(keyFile, sigType, expiration, \
                    generation, target_sha256, duration)
                
    def update(self, keyFile, sigType, expiration, \
                generation, target_sha256, duration):
        """Create a new TACK_Sig for the TACK.

        The existing TACK_Sig is replaced.  The existing TACK_Key is 
        unmodified.  The duration value is changed.
        """                        
        self.sig = TACK_Sig()
        self.sig.create(sigType, expiration, generation, 
                            target_sha256, self.key, keyFile.sign)
        self.duration = duration

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
        self.duration = p.getInt(4)
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
        w.add(self.duration, 4)
        return w.bytes

    def writeText(self):
        """Return a readable string describing this TACK.
        
        Used by the "TACK view" command to display TACK objects."""        
        s =\
"""%s%s""" % \
            (self.key.writeText(), self.sig.writeText())
        s += \
"""duration       = %s\n""" % durationToStr(self.duration)
        return s   
        
class TACK_Break_Sig:
    length = 64 + TACK_Key.length  # totals 137
    
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
            raise SyntaxError("TACK is the wrong size")        
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
        self.type = 0 # 8-bit type from TACK_Extension_Type
        self.tack = None
        self.break_sigs = None # aka []
        
    def create(self, tack=None, break_sigs=None):
        self.type = TACK_Extension_Type.v1
        self.tack = tack
        self.break_sigs = break_sigs        
    
    def isEmpty():
        return (not self.tack and not self.break_sigs)

    def parse(self, b):
        p = Parser(b)
        self.type = p.getInt(1)
        if self.type != TACK_Extension_Type.v1:
            raise SyntaxError("Bad TACK_Extension type")
        tackLen = p.getInt(1)
        if tackLen:
            if tackLen != TACK.length:
                raise SyntaxError("Only supports v1 TACKs")
            self.tack = TACK()
            self.tack.parse(p.getBytes(tackLen))
        sigsLen = p.getInt(2)
        if sigsLen % TACK_Break_Sig.length != 0:
            raise SyntaxError("Bad length in TACK_Break_Sig")
        if sigsLen // TACK_Break_Sig.length > 10:
            raise SyntaxError("Too many Break Sigs")
        self.break_sigs = []            
        while sigsLen:
            b2 = p.getBytes(TACK_Break_Sig.length)
            breakSig = TACK_Break_Sig()
            breakSig.parse(b2)
            self.break_sigs.append(breakSig)
            sigsLen -= TACK_Break_Sig.length
        if p.index != len(b):
            raise SyntaxError("Excess bytes in TACK_Extension")

    def write(self):
        length = 0
        if self.tack:
            length += TACK.length
        if self.break_sigs:
            length += len(self.break_sigs) * TACK_Break_Sig.length
        w = Writer(length+4)
        w.add(self.type, 1)
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
        assert(w.index == len(w.bytes)) # did we fill entire bytearray?
        return w.bytes
            
        
            
    
def writeTextTACKStructures(tack, breakSigs, tackidOnly=False):        
    s = ""
    if tack:
        if not tackidOnly:
            s += tack.writeText()
        else:
            s += tack.getTACKID()+"\n"
    if breakSigs:
        s += ("\n")
        for breakSig in breakSigs:
            s += breakSig.writeText()
    return s

def testTACKStructures():
    print("Testing TACK STRUCTURES")
    s = """
-----BEGIN TACK-----
AcXtBwiabuCnAgX+5AaL5Bku+yLj48GmWrT2CWwTOVFJOHW9ml2btOkBhgVqpza8
8Izv6YH/cuUK176UFsKyzB/rmvvBFv9cLwIByHCTAgntbpkfwyc9j+oxfTOcAgQY
YZc1Sc+m4VWPQR8RIRqj4DewzYA1QnWCBiDwojfe4XY7PeRNPGSlhgdvF9XFe8UB
+gsjLjUkqPJDk0fjDYHwspY2MiwlRITG51j/1vlhKQAAqMA=
-----END TACK-----"""
    t = TACK()
    t.parsePem(s)
    assert(t.key.type == TACK_Key_Type.v1)
    assert(t.key.public_key == a2b_hex("c5ed07089a6ee0a70205fee4068be4192efb22e3e3c1a65ab4f6096c13395149"+
                       "3875bd9a5d9bb4e90186056aa736bcf08cefe981ff72e50ad7be9416c2b2cc1f"))
    assert(t.key.nonce == a2b_hex("eb9afbc116ff5c2f"))
    assert(t.sig.type == TACK_Sig_Type.v1_cert)
    assert(posixTimeToStr(t.sig.expiration*60) == "2026-11-16T01:55Z")
    assert(t.sig.generation == 2)
    assert(t.sig.target_sha256 == a2b_hex("09ed6e991fc3273d8fea317d339c0204"+
                                       "1861973549cfa6e1558f411f11211aa3"))
    assert(t.sig.signature == a2b_hex("e037b0cd80354275820620f0a237dee1" + 
                                   "763b3de44d3c64a586076f17d5c57bc5" + 
                                   "01fa0b232e3524a8f2439347e30d81f0" + 
                                   "b29636322c254484c6e758ffd6f96129"))
    s = """
-----BEGIN TACK BREAK SIG-----
AcXtBwiabuCnAgX+5AaL5Bku+yLj48GmWrT2CWwTOVFJOHW9ml2btOkBhgVqpza8
8Izv6YH/cuUK176UFsKyzB+4EWiVTg109+XeXctHNIYr6ZsqM7MHR+ClMWYnM0De
Nv4iPe0BhWHNV9x7KBMC+cE8pcGohrTXxiVTGjAO32k4vGQst4VQSgk=
-----END TACK BREAK SIG-----"""
    tbs = TACK_Break_Sig()
    tbs.parsePem(s)
    assert(tbs.key.type == TACK_Key_Type.v1)
    assert(tbs.key.public_key == a2b_hex("c5ed07089a6ee0a70205fee4068be419"+
                       "2efb22e3e3c1a65ab4f6096c13395149"+
                       "3875bd9a5d9bb4e90186056aa736bcf0"+
                       "8cefe981ff72e50ad7be9416c2b2cc1f"))
    assert(tbs.key.nonce == a2b_hex("b81168954e0d74f7"))
    assert(tbs.signature == a2b_hex("e5de5dcb4734862be99b2a33b30747e0"+
                       "a53166273340de36fe223ded018561cd"+
                       "57dc7b281302f9c13ca5c1a886b4d7c6"+
                       "25531a300edf6938bc642cb785504a09"))
    s = """                       
Created by TACK.py 0.9.3
Created at 2012-02-01T00:30:10Z
-----BEGIN TACK BREAK SIG-----
ATKhrz5C6JHJW8BF5fLVrnQss6JnWVyEaC0p89LNhKPswvcC9/s6+vWLd9snYTUv
YMEBdw69PUP8JB4AdqA3K6Ap0Fgd9SSTOECeAKOUAym8zcYaXUwpk0+WuPYa7Zmm
SkbOlK4ywqt+amhWbg9txSGUwFO5tWUHT3QrnRlE/e3PeNFXLx5Bckg=
-----END TACK BREAK SIG-----
Created by TACK.py 0.9.3
Created at 2012-02-01T00:30:11Z
-----BEGIN TACK BREAK SIG-----
ATKhrz5C6JHJW8BF5fLVrnQss6JnWVyEaC0p89LNhKPswvcC9/s6+vWLd9snYTUv
YMEBdw69PUP8JB4AdqA3K6BVCWfcjN36lx6JwxmZQncS6sww7DecFO/qjSePCxwM
+kdDqX/9/183nmjx6bf0ewhPXkA0nVXsDYZaydN8rJU1GaMlnjcIYxY=
-----END TACK BREAK SIG-----
"""
    tbsList = TACK_Break_Sig.parsePemList(s)
    assert(tbsList[0].getTACKID()  == "BHMXG.NIUGC.4D9EG.BRLP1.DTQBE")
    assert(tbsList[1].getTACKID()  == "BWDJY.IDCEA.74IDQ.X4DG9.MRIMS")
    assert(len(tbsList) == 2)
    return 1
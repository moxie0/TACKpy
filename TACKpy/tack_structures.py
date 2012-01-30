from constants import *
from struct_parser import *
from time_funcs import *
from misc import *
from pem import *
from ecdsa_wrappers import *

################ TACK STRUCTURES ###

import os # for os.urandom
        
class TACK_Pin:
    length = 73 # length of TACK_Pin in bytes
    
    def __init__(self):
        """Create an uninitialized TACK_Pin.  
        
        Use create() or parse() to populate."""
        self.type = 0 # integer from TACK_Pin_Type
        self.key = bytearray(64) # EC public key using NIST-P256
        self.label = bytearray(8)
    
    def create(self, key):
        """Initialize a TACK_Pin, based on the input key 32-byte bytearray.
        
        The label is randomized to distinguish this from other pins based
        on the same key."""
        self.type = TACK_Pin_Type.v1
        assert(len(key) == 64)
        self.key = key
        self.label = os.urandom(8)
            
    def parse(self, b):
        """Parse a bytearray of 73 bytes to populate this TACK_Pin.
        
        Raise a SyntaxError if input is malformed.
        """
        p = Parser(b)
        self.type = p.getInt(1)
        if self.type != TACK_Pin_Type.v1:
            raise SyntaxError("Bad pin.type")
        self.key = p.getBytes(64)
        self.label = p.getBytes(8)
        if p.index != len(b):
            raise SyntaxError("Excess bytes in TACK_Pin")        
        
    def write(self):        
        """Return a 73-byte bytearray encoding of this TACK_Pin."""
        assert(self.type == TACK_Pin_Type.v1)        
        w = Writer(TACK_Pin.length)
        w.add(self.type, 1)
        w.add(self.key, 64)
        w.add(self.label, 8)  
        assert(w.index == len(w.bytes)) # did we fill entire bytearray?            
        return w.bytes  

    def writeText(self):
        """Return a readable string describing this TACK_Pin.
        
        Used by the "TACK view" command to display TACK objects."""
        assert(self.type == TACK_Pin_Type.v1)
        s = \
"""pin.type       = %s
key            = 0x%s
label          = 0x%s\n""" % \
(TACK_Pin_Type.strings[self.type], 
writeBytes(self.key),
writeBytes(self.label))
        return s
        
           
class TACK_Sig:
    length = 102 # length of TACK_Sig in bytes
        
    def __init__(self):
        """Create an uninitialized TACK_Sig.  
        
        Use create() or parse() to populate."""        
        self.type = 0 # 8-bit value from TACK_Pin_Type (v1_cert or v1_key)
        self.expiration = 0 # 32-bit unsigned integer encoding POSIX time
        self.generation = 0 # 8-bit integer               
        self.target_sha256 = bytearray(32) # 32-byte SHA256 result
        self.signature = bytearray(64) # ECDSA signature using NIST-P256
        
    def create(self, type, expiration, generation,
                target_sha256, pin, signFunc):
        """Initialize a TACK_Sig.

        The input args are mostly used to set TACK_Sig fields directly.
        However, the last two args contain a TACK_Pin object and an ECDSA
        signing function, which are used to populate the "signature" value. 
        
        The signing function takes an input bytearray, and returns a
        64-byte signature of the bytearray based on ECDSA-NIST-P256-SHA256.
        
        To calculate the signing function input, the TACK_Pin is written to a 
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
        self.signature = signFunc(pin.write() + self.write()[:-64])
    
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
target_sha256  = 0x%s
signature      = 0x%s\n""" % \
(TACK_Sig_Type.strings[self.type], 
posixTimeToStr(self.expiration*60),
self.generation,
writeBytes(self.target_sha256),
writeBytes(self.signature))
        return s

class TACK:
    length = 4 + TACK_Pin.length + TACK_Sig.length  # 179 bytes
    
    def __init__(self):
        """Create an uninitialized TACK.  
        
        Use create() or parsePem() to populate."""        
        self.pin = None # class TACK_Pin
        self.sig = None # class TACK_Sig
        self.duration = 0 # 32-bit unsigned integer, counting minutes

    def create(self, keyFile, sigType, expiration, \
                generation, target_sha256, duration):
        """Initialize a TACK.

        The input args are passed to TACK_Pin.create() or TACK_Sig.create(),
        except for duration which is applied directly to self.duration.
        """        
        self.pin = TACK_Pin()
        self.pin.create(keyFile.public_key)
        self.update(keyFile, sigType, expiration, \
                    generation, target_sha256, duration)
                
    def update(self, keyFile, sigType, expiration, \
                generation, target_sha256, duration):
        """Create a new TACK_Sig for the TACK.

        The existing TACK_Sig is replaced.  The existing TACK_Pin is 
        unmodified.  The duration value is changed.
        """                        
        self.sig = TACK_Sig()
        self.sig.create(sigType, expiration, generation, 
                            target_sha256, self.pin, keyFile.sign)
        self.duration = duration

    def verifySignature(self):
        bytesToVerify = self.pin.write() + self.sig.write()[:-64]
        return ecdsa256Verify(self.pin.key, bytesToVerify, self.sig.signature)  

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
        self.pin = TACK_Pin()
        self.sig = TACK_Sig()
        self.pin.parse(b[ : TACK_Pin.length])
        b = b[TACK_Pin.length : ]
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
        w.add(self.pin.write(), TACK_Pin.length) 
        w.add(self.sig.write(), TACK_Sig.length)
        w.add(self.duration, 4)
        return w.bytes

    def writeText(self):
        """Return a readable string describing this TACK.
        
        Used by the "TACK view" command to display TACK objects."""        
        s =\
"""
TACK_Pin
=========
%s
TACK_Sig
=========
%s""" % \
            (self.pin.writeText(), self.sig.writeText())
        s += \
"""\nDuration
=========
duration       = %s\n""" % durationToStr(self.duration)
        return s   
        
class TACK_Break_Sig:
    length = 64 + TACK_Pin.length  # 137
    
    def __init__(self):
        """Create an uninitialized TACK_Break_Sig.  
        
        Use create() or parsePem() to populate."""        
        self.pin = None # TACK_Pin
        self.signature = bytearray(64) # ECDSA signature on TACK_Pin
        
    def create(self, pin, signature):
        """Initialize a TACK_Break_Sig with a TACK_Pin and 64-byte bytearray.
        """        
        assert(len(signature) == 64)
        self.pin = pin
        self.signature = signature
        
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
        self.pin = TACK_Pin()
        self.pin.parse(b[ : TACK_Pin.length])
        b = b[TACK_Pin.length : ]  
        p = Parser(b)      
        self.signature = p.getBytes(64)
        if p.index != len(b):
            raise SyntaxError("Excess bytes in TACK_Break_Sig")
        
    def writePem(self):
        """Return a string containing a PEM file for the TACK_Break_Sig."""        
        w = Writer(TACK_Break_Sig.length)
        w.add(self.pin.write(), TACK_Pin.length)
        w.add(self.signature, 64)
        assert(w.index == len(w.bytes)) # did we fill entire bytearray?        
        return pem(w.bytes, "TACK BREAK SIG")

    def writeText(self):
        """Return a readable string describing this TACK_Break_Sig.
        
        Used by the "TACK view" command to display TACK objects."""        
        s = self.pin.writeText()
        s += "signature      = 0x%s\n" % (writeBytes(self.signature))
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
    assert(t.pin.type == TACK_Pin_Type.v1)
    assert(t.pin.key == a2b_hex("c5ed07089a6ee0a70205fee4068be4192efb22e3e3c1a65ab4f6096c13395149"+
                       "3875bd9a5d9bb4e90186056aa736bcf08cefe981ff72e50ad7be9416c2b2cc1f"))
    assert(t.pin.label == a2b_hex("eb9afbc116ff5c2f"))
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
    assert(tbs.pin.type == TACK_Pin_Type.v1)
    assert(tbs.pin.key == a2b_hex("c5ed07089a6ee0a70205fee4068be419"+
                       "2efb22e3e3c1a65ab4f6096c13395149"+
                       "3875bd9a5d9bb4e90186056aa736bcf0"+
                       "8cefe981ff72e50ad7be9416c2b2cc1f"))
    assert(tbs.pin.label == a2b_hex("b81168954e0d74f7"))
    assert(tbs.signature == a2b_hex("e5de5dcb4734862be99b2a33b30747e0"+
                       "a53166273340de36fe223ded018561cd"+
                       "57dc7b281302f9c13ca5c1a886b4d7c6"+
                       "25531a300edf6938bc642cb785504a09"))
    return 1
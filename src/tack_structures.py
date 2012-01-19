from constants import *
from struct_parser import *
from time_funcs import *
from misc import *
from pem import *

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
        """Create a new TACK_Pin, based on the input key 32-byte bytearray.
        
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
            raise SyntaxError()
        self.key = p.getBytes(64)
        self.label = p.getBytes(8)
        assert(p.index == len(b)) # did we fully consume bytearray?
        
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
        """Create an uninitialized TACK_Pin.  
        
        Use create() or parse() to populate."""        
        self.type = 0 # 8-bit value from TACK_Pin_Type (v1_cert or v1_key)
        self.expiration = 0 # 32-bit unsigned integer encoding POSIX time
        self.generation = 0 # 8-bit integer               
        self.target_sha256 = bytearray(32) # 32-byte SHA256 result
        self.signature = bytearray(64) # ECDSA signature using NIST-P256
        
    def create(self, type, expiration, generation,
                target_sha256, pin, signFunc):
        """Create a new TACK_Sig.

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
            raise SyntaxError()
        self.expiration = p.getInt(4)
        self.generation = p.getInt(1)            
        self.target_sha256 = p.getBytes(32)
        self.signature = p.getBytes(64)
        assert(p.index == len(b)) # did we fully consume bytearray?
        
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
        self.pin = TACK_Pin()
        self.pin.create(keyFile.public_key)
        self.update(keyFile, sigType, expiration, \
                    generation, target_sha256, duration)
                
    def update(self, keyFile, sigType, expiration, \
                generation, target_sha256, duration):
        self.sig = TACK_Sig()
        self.sig.create(sigType, expiration, generation, 
                            target_sha256, self.pin, keyFile.sign)
        self.duration = duration

    def parsePem(self, b):
        b = dePem(b, "TACK")                
        assert(len(b) == TACK_Pin.length + TACK_Sig.length + 4)
        self.pin = TACK_Pin()
        self.sig = TACK_Sig()
        self.pin.parse(b[ : TACK_Pin.length])
        b = b[TACK_Pin.length : ]
        self.sig.parse(b[ : TACK_Sig.length])
        b = b[TACK_Sig.length : ]
        p = Parser(b)
        self.duration = p.getInt(4)
        assert(p.index == len(b)) # did we fully consume bytearray?

    def writePem(self):
        w = Writer(TACK_Pin.length + TACK_Sig.length + 4)
        w.add(self.pin.write(), TACK_Pin.length) 
        w.add(self.sig.write(), TACK_Sig.length)
        w.add(self.duration, 4)
        return pem(w.bytes, "TACK")

    def writeText(self):
        s =\
"""
TACK_Pin
---------
%s
TACK_Sig
---------
%s""" % \
            (self.pin.writeText(), self.sig.writeText())
        s += \
"""\nDuration
---------
duration       = %s\n""" % durationToStr(self.duration)
        return s   
        
class TACK_Break_Sig:
    length = 64 + TACK_Pin.length  # 137
    
    def __init__(self):
        self.pin = None
        self.signature = bytearray(64)
        
    def create(self, pin, signature):
        self.pin = pin
        self.signature = signature
        
    def parsePem(self, b):
        b = dePem(b, "TACK BREAK SIG")
        p = Parser(b)
        self.pin = TACK_Pin()
        self.pin.parse(b[ : TACK_Pin.length])
        b = b[TACK_Pin.length : ]  
        p = Parser(b)      
        self.signature = p.getBytes(64)
        assert(p.index == len(b)) # did we fully consume bytearray?
        
    def writePem(self):
        w = Writer(TACK_Break_Sig.length)
        w.add(self.pin.write(), TACK_Pin.length)
        w.add(self.signature, 64)
        assert(w.index == len(w.bytes)) # did we fill entire bytearray?        
        return pem(w.bytes, "TACK BREAK SIG")

    def writeText(self):
        s = self.pin.writeText()
        s += "signature      = 0x%s\n" % (writeBytes(self.signature))
        return s

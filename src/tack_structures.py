from constants import *
from struct_parser import *
from time_funcs import *
from misc import *
from pem import *

################ TACK STRUCTURES ###

import os # for os.urandom
        
class TACK_Pin:
    length = 73
    
    def __init__(self):
        self.type = 0
        self.key = bytearray(64)
        self.label = bytearray(8)
    
    def generate(self, key):
        self.type = TACK_Pin_Type.v1
        self.key = key
        self.label = os.urandom(8)
            
    def parse(self, b):
        p = Parser(b)
        self.type = p.getInt(1)
        if self.type != TACK_Pin_Type.v1:
            raise SyntaxError()
        self.key = p.getBytes(64)
        self.label = p.getBytes(8)
        assert(p.index == len(b)) # did we fully consume byte-array?
        
    def write(self):        
        if self.type != TACK_Pin_Type.v1:
            raise SyntaxError()        
        w = Writer(TACK_Pin.length)
        w.add(self.type, 1)
        w.add(self.key, 64)
        w.add(self.label, 8)  
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?            
        return w.bytes  

    def writeText(self):
        if self.type != TACK_Pin_Type.v1:
            raise SyntaxError()
        s = \
"""pin.type       = %s
key            = 0x%s
label          = 0x%s\n""" % \
(TACK_Pin_Type.strings[self.type], 
writeBytes(self.key),
writeBytes(self.label))
        return s
        
           
class TACK_Sig:
    length = 102
        
    def __init__(self):
        self.type = 0
        self.expiration = 0
        self.generation = 0                
        self.target_sha256 = bytearray(32)
        self.signature = bytearray(64)
        
    def generate(self, type, expiration, generation,
                target_sha256, pin, signFunc):
        self.type = type
        self.expiration = expiration
        self.generation = generation                
        self.target_sha256 = target_sha256
        self.signature = signFunc(pin.write() + self.write()[:-64])
    
    def parse(self, b):
        p = Parser(b)
        self.type = p.getInt(1)
        if self.type not in TACK_Sig_Type.all:
            raise SyntaxError()
        self.expiration = p.getInt(4)
        self.generation = p.getInt(1)            
        self.target_sha256 = p.getBytes(32)
        self.signature = p.getBytes(64)
        assert(p.index == len(b)) # did we fully consume byte-array?
        
    def write(self):
        if self.type not in TACK_Sig_Type.all:
            raise SyntaxError()
        w = Writer(TACK_Sig.length)
        w.add(self.type, 1)
        w.add(self.expiration, 4)
        w.add(self.generation, 1)
        w.add(self.target_sha256, 32)
        w.add(self.signature, 64)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?
        return w.bytes

    def writeText(self):
        if self.type not in TACK_Sig_Type.all:
            raise SyntaxError()
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
    def __init__(self):
        self.pin = None
        self.sig = None
        self.duration = 0

    def create(self, keyFile, sigType, expiration, \
                generation, target_sha256, duration):
        self.pin = TACK_Pin()
        self.pin.generate(keyFile.public_key)
        self.update(keyFile, sigType, expiration, \
                    generation, target_sha256, duration)
                
    def update(self, keyFile, sigType, expiration, \
                generation, target_sha256, duration):
        self.sig = TACK_Sig()
        self.sig.generate(sigType, expiration, generation, 
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
        assert(p.index == len(b)) # did we fully consume byte-array?

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
    length = 64 + TACK_Pin.length
    
    def __init__(self):
        self.pin = None
        self.signature = bytearray(64)
        
    def generate(self, pin, signature):
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
        assert(p.index == len(b)) # did we fully consume byte-array?
        
    def writePem(self):
        w = Writer(TACK_Break_Sig.length)
        w.add(self.pin.write(), TACK_Pin.length)
        w.add(self.signature, 64)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?        
        return pem(w.bytes, "TACK BREAK SIG")

    def writeText(self):
        s = self.pin.writeText()
        s += "signature      = 0x%s\n" % (writeBytes(self.signature))
        return s

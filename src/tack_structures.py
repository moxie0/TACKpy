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
        self.pin_type = 0
        self.pin_key = bytearray(64)
        self.pin_label = bytearray(8)
    
    def generate(self, pin_key):
        self.pin_type = TACK_Pin_Type.v1
        self.pin_key = pin_key
        self.pin_label = os.urandom(8)
            
    def parse(self, b):
        p = Parser(b)
        self.pin_type = p.getInt(1)
        if self.pin_type != TACK_Pin_Type.v1:
            raise SyntaxError()
        self.pin_key = p.getBytes(64)
        self.pin_label = p.getBytes(8)
        assert(p.index == len(b)) # did we fully consume byte-array?
        
    def write(self):        
        if self.pin_type != TACK_Pin_Type.v1:
            raise SyntaxError()        
        w = Writer(TACK_Pin.length)
        w.add(self.pin_type, 1)
        w.add(self.pin_key, 64)
        w.add(self.pin_label, 8)  
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?            
        return w.bytes  

    def writeText(self):
        if self.pin_type != TACK_Pin_Type.v1:
            raise SyntaxError()
        s = \
"""pin_type               = %s
pin_key                = 0x%s
pin_label              = 0x%s\n""" % \
(TACK_Pin_Type.strings[self.pin_type], 
writeBytes(self.pin_key),
writeBytes(self.pin_label))
        return s
        
           
class TACK_Sig:
    length = 102
        
    def __init__(self):
        self.sig_type = 0
        self.sig_expiration = 0
        self.sig_generation = 0                
        self.sig_target_sha256 = bytearray(32)
        self.signature = bytearray(64)
        
    def generate(self, sig_type, sig_expiration, sig_generation,
                sig_target_sha256, pin, signFunc):
        self.sig_type = sig_type
        self.sig_expiration = sig_expiration
        self.sig_generation = sig_generation                
        self.sig_target_sha256 = sig_target_sha256
        self.signature = signFunc(pin.write() + self.write()[:-64])
    
    def parse(self, b):
        p = Parser(b)
        self.sig_type = p.getInt(1)
        if self.sig_type not in TACK_Sig_Type.all:
            raise SyntaxError()
        self.sig_expiration = p.getInt(4)
        self.sig_generation = p.getInt(1)            
        self.sig_target_sha256 = p.getBytes(32)
        self.signature = p.getBytes(64)
        assert(p.index == len(b)) # did we fully consume byte-array?
        
    def write(self):
        if self.sig_type not in TACK_Sig_Type.all:
            raise SyntaxError()
        w = Writer(TACK_Sig.length)
        w.add(self.sig_type, 1)
        w.add(self.sig_expiration, 4)
        w.add(self.sig_generation, 1)
        w.add(self.sig_target_sha256, 32)
        w.add(self.signature, 64)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?
        return w.bytes

    def writeText(self):
        if self.sig_type not in TACK_Sig_Type.all:
            raise SyntaxError()
        s = \
"""sig_type               = %s
sig_expiration         = %s
sig_generation         = %d
sig_target_sha256      = 0x%s
signature              = 0x%s\n""" % \
(TACK_Sig_Type.strings[self.sig_type], 
posixTimeToStr(self.sig_expiration*60),
self.sig_generation,
writeBytes(self.sig_target_sha256),
writeBytes(self.signature))
        return s

class TACK:
    def __init__(self):
        self.pin = None
        self.sig = None
        self.pin_duration = 0

    def create(self, keyFile, sig_type, sig_expiration, \
                sig_generation, sig_target_sha256, pin_duration):
        self.pin = TACK_Pin()
        self.pin.generate(keyFile.public_key)
        self.update(keyFile, sig_type, sig_expiration, \
                    sig_generation, sig_target_sha256, pin_duration)
                
    def update(self, keyFile, sig_type, sig_expiration, \
                sig_generation, sig_target_sha256, pin_duration):
        self.sig = TACK_Sig()
        self.sig.generate(sig_type, sig_expiration, sig_generation, 
                            sig_target_sha256, self.pin, keyFile.sign)
        self.pin_duration = pin_duration

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
        self.pin_duration = p.getInt(4)
        assert(p.index == len(b)) # did we fully consume byte-array?

    def writePem(self):
        w = Writer(TACK_Pin.length + TACK_Sig.length + 4)
        w.add(self.pin.write(), TACK_Pin.length) 
        w.add(self.sig.write(), TACK_Sig.length)
        w.add(self.pin_duration, 4)
        return pem(w.bytes, "TACK")

    def writeText(self):
        s ="%s%s" % \
            (self.pin.writeText(), self.sig.writeText())
        s += "pin_duration           = %s\n" % durationToStr(self.pin_duration)
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
        s = "break_sig:\n" + self.pin.writeText()
        s += "break_signature        = 0x%s\n" % (writeBytes(self.signature))
        return s

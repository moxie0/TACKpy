from constants import *
from struct_parser import *
from time_funcs import *

################ TACK STRUCTURES ###
        
class TACK_Pin:
    length = 77
    
    def __init__(self):
        self.pin_type = 0
        self.pin_expiration = 0
        self.pin_label = bytearray(8)
        self.pin_key = bytearray(64)
    
    def generate(self, pin_type, pin_expiration, pin_label, pin_key):
        self.pin_type = pin_type
        self.pin_expiration = pin_expiration
        self.pin_label = pin_label
        self.pin_key = pin_key
            
    def parse(self, b):
        p = Parser(b)
        self.pin_type = p.getInt(1)
        if self.pin_type != TACK_Pin_Type.v1:
            raise SyntaxError()
        self.pin_expiration = p.getInt(4)
        self.pin_label = p.getBytes(8)
        self.pin_key = p.getBytes(64)
        assert(p.index == len(b)) # did we fully consume byte-array?
        
    def write(self):        
        if self.pin_type != TACK_Pin_Type.v1:
            raise SyntaxError()        
        w = Writer(TACK_Pin.length)
        w.add(self.pin_type, 1)
        w.add(self.pin_expiration, 4)
        w.add(self.pin_label, 8)  
        w.add(self.pin_key, 64)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?            
        return w.bytes  

    def writeText(self):
        if self.pin_type != TACK_Pin_Type.v1:
            raise SyntaxError()
        s = \
"""pin_type               = %s
pin_expiration         = %s
pin_label              = 0x%s
pin_key                = 0x%s\n""" % \
(TACK_Pin_Type.strings[self.pin_type], 
posixTimeToStr(self.pin_expiration*60),
writeBytes(self.pin_label),
writeBytes(self.pin_key))
        return s
        
           
class TACK_Sig:
    length = 105
        
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
        self.signature = signFunc(self.write()[:-64] + pin.pin_label)
    
    def parse(self, b):
        p = Parser(b)
        self.sig_type = p.getInt(1)
        if self.sig_type not in TACK_Sig_Type.all:
            raise SyntaxError()
        self.sig_expiration = p.getInt(4)
        self.sig_generation = p.getInt(4)            
        self.sig_target_sha256 = p.getBytes(32)
        self.signature = p.getBytes(64)
        assert(p.index == len(b)) # did we fully consume byte-array?
        
    def write(self):
        if self.sig_type not in TACK_Sig_Type.all:
            raise SyntaxError()
        w = Writer(TACK_Sig.length)
        w.add(self.sig_type, 1)
        w.add(self.sig_expiration, 4)
        w.add(self.sig_generation, 4)
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
sig_generation         = %s
sig_target_sha256      = 0x%s
signature              = 0x%s\n""" % \
(TACK_Sig_Type.strings[self.sig_type], 
posixTimeToStr(self.sig_expiration*60),
posixTimeToStr(self.sig_generation*60),
writeBytes(self.sig_target_sha256),
writeBytes(self.signature))
        return s
   
        
class TACK_Break_Sig:
    length = 72
    
    def __init__(self):
        self.pin_label = bytearray(8)
        self.signature = bytearray(64)
        
    def generate(self, pin_label, signature):
        self.pin_label = pin_label
        self.signature = signature
        
    def parse(self, b):
        p = Parser(b)
        self.pin_label = p.getBytes(8)
        self.signature = p.getBytes(64)
        assert(p.index == len(b)) # did we fully consume byte-array?
        
    def write(self):
        w = Writer(TACK_Break_Sig.length)
        w.add(self.pin_label, 8)
        w.add(self.signature, 64)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?        
        return w.bytes

    def writeText(self, i):
        s = \
"""break_label[%02d]        = 0x%s
break_signature[%02d]    = 0x%s\n""" % \
(i, writeBytes(self.pin_label), 
 i, writeBytes(self.signature))
        return s


class TACK_Break_Sigs:
    maxLen = 20
    
    def __init__(self):
        self.break_sigs = []
    
    def isFull(self):
        return len(self.break_sigs) == TACK_Break_Sigs.maxLen
    
    def add(self, break_sig):
        assert(len(self.break_sigs) < TACK_Break_Sigs.maxLen)
        assert(isinstance(break_sig, TACK_Break_Sig))
        self.break_sigs.append(break_sig)
    
    def parse(self, b):
        p = Parser(b)
        numBreakSigs = int(p.getInt(2) // TACK_Break_Sig.length)
        if numBreakSigs > TACK_Break_Sigs.maxLen:
            raise SyntaxError("Too many break_sigs")
        self.break_sigs = []
        for x in range(numBreakSigs):
            break_sig = TACK_Break_Sig()
            break_sig.parse(p.getBytes(TACK_Break_Sig.length))
            self.break_sigs.append(break_sig)
    
    def write(self):
        w = Writer(2 + TACK_Break_Sig.length * len(self.break_sigs))
        w.add(len(self.break_sigs) * TACK_Break_Sig.length, 2)
        for x in range(len(self.break_sigs)):
            w.add(self.break_sigs[x].write(), TACK_Break_Sig.length)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?                    
        return w.bytes

    def writeText(self):
        return "".join(b.writeText(i) for i,b in enumerate(self.break_sigs))


class TACK:
    def __init__(self):
        self.pin = None
        self.sig = None
        
    def parse(self, b):
        assert(len(b) == TACK_Pin.length + TACK_Sig.length)
        self.pin = TACK_Pin()
        self.sig = TACK_Sig()
        self.pin.parse(b[ : TACK_Pin.length])
        b = b[TACK_Pin.length : ]
        self.sig.parse(b[ : TACK_Sig.length])
        
    def write(self):
        w = Writer(TACK_Pin.length + TACK_Sig.length)
        w.add(self.pin.write(), TACK_Pin.length) 
        w.add(self.sig.write(), TACK_Sig.length)
        return w.bytes

    def writeText(self):
        return "%s%s" % \
            (self.pin.writeText(), self.sig.writeText())

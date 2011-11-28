#! /usr/bin/env python


################ CRYPTOMATH ###

import math, hashlib, hmac

def bytesToNumber(bytes):
    total = 0L
    multiplier = 1L
    for count in range(len(bytes)-1, -1, -1):
        byte = bytes[count]
        total += multiplier * byte
        multiplier *= 256
    return total

def numberToBytes(n, howManyBytes=None):
    if not howManyBytes:
        howManyBytes = numBytes(n)
    bytes = bytearray(howManyBytes)
    for count in range(howManyBytes-1, -1, -1):
        bytes[count] = int(n % 256)
        n >>= 8
    return bytes
    
def stringToNumber(s):
    return bytesToNumber(bytearray(s))
    
def numBits(n):
    if n==0:
        return 0
    s = "%x" % n
    return ((len(s)-1)*4) + \
    {'0':0, '1':1, '2':2, '3':2,
     '4':3, '5':3, '6':3, '7':3,
     '8':4, '9':4, 'a':4, 'b':4,
     'c':4, 'd':4, 'e':4, 'f':4,
     }[s[0]]
    
def numBytes(n):
    if n==0:
        return 0
    bits = numBits(n)
    return int(math.ceil(bits / 8.0))

def SHA256(b):
    return bytearray(hashlib.sha256(b).digest())

def HMAC_SHA256(k, b):
    return bytearray(hmac.new(k, b, hashlib.sha256).digest())

def constTimeCompare(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x in range(len(a)):
        result |= a[x]^b[x]
    if result:
        return False
    return True

################ TIME ###

import time, datetime

def timeUintToStr(u):    
    t = time.gmtime(60*u)
    s = time.strftime("%Y-%m-%dT%H:%MZ", t)
    return s

################ CODEC ###

class Writer:
    def __init__(self, totalLength):
        self.index = 0
        self.bytes = bytearray(totalLength)

    def add(self, x, elementLength):
        """Writes 'elementLength' bytes, input is either an integer
         (written as big-endian) or a sequence of bytes"""
        if isinstance(x, int):
            assert(x >= 0 and x < 2**(8*elementLength))
            newIndex = self.index + elementLength-1
            while newIndex >= self.index:
                self.bytes[newIndex] = x & 0xFF
                x >>= 8
                newIndex -= 1
        else:
            assert(len(x) == elementLength)
            for i in xrange(elementLength):
                self.bytes[self.index + i] = x[i]                
        self.index += elementLength

    def addVarSeq(self, seq, elementLength, lengthLength):
        """Writes a sequence of elements prefixed by a 
        total-length field of lengthLength bytes"""
        self.add(len(seq)*elementLength, lengthLength)
        for e in seq:
            self.add(e, elementLength)

class Parser:
    def __init__(self, bytes):
        self.bytes = bytes
        self.index = 0

    def getInt(self, elementLength):
        """Reads an integer of 'length' bytes"""
        if self.index + elementLength > len(self.bytes):
            raise SyntaxError()
        x = 0
        for count in range(elementLength):
            x <<= 8
            x |= self.bytes[self.index]
            self.index += 1
        return x

    def getBytes(self, elementLength):
        """Reads some number of bytes as determined by 'lengthBytes'"""
        bytes = self.bytes[self.index : self.index + elementLength]
        self.index += elementLength
        return bytes

    def getVarSeqBytes(self, elementLength, lengthLength):
        dataLength = self.getInt(lengthLength)
        if dataLength % elementLength != 0:
            raise SyntaxError()
        return [self.getBytes(elementLength) for x in \
                range(dataLength/elementLength)]


################ CONSTANTS ###

class TACK_Pin_Type:
    in_chain_key = 1
    in_chain_cert = 2    
    out_of_chain_key = 3
    all = (in_chain_key, in_chain_cert, out_of_chain_key)

class TACK_Sig_Type:
    in_chain_key = 1
    in_chain_cert = 2
    all = (in_chain_key, in_chain_cert)
        

################ STRUCTURES ###
        
class TACK_Pin:
    def __init__(self):
        self.pin_type = 0
        self.pin_expiration = 0
        self.pin_target_sha256 = bytearray(32)
        self.pin_break_code_sha256 = bytearray(32)        
    
    def parse(self, b):
        p = Parser(b)
        self.pin_type = p.getInt(1)
        if self.pin_type not in TACK_Pin_Type.all:
            raise SyntaxError()
        self.pin_expiration = p.getInt(4)
        self.pin_target_sha256 = p.getBytes(32)
        self.pin_break_code_sha256 = p.getBytes(32)
        assert(p.index == len(b)) # did we fully consume byte-array?
        
    def write(self):        
        if self.pin_type not in TACK_Pin_Type.all:
            raise SyntaxError()        
        w = Writer(69)
        w.add(self.pin_type, 1)
        w.add(self.pin_expiration, 4)
        w.add(self.pin_target_sha256, 32)  
        w.add(self.pin_break_code_sha256, 32)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?            
        return w.bytes  
     
        
class TACK_Sig:    
    def __init__(self):
        self.sig_type = 0
        self.sig_expiration = 0
        self.sig_generation = 0                
        self.target_sha256 = bytearray(32)
        self.out_of_chain_key = bytearray(64)
        self.signature = bytearray(64)
    
    def parse(self, b):
        p = Parser(b)
        self.sig_type = p.getInt(1)
        if self.sig_type not in TACK_Sig_Type.all:
            raise SyntaxError()
        self.sig_expiration = p.getInt(4)
        self.sig_generation = p.getInt(4)            
        self.sig_target_sha256 = p.getBytes(32)
        self.out_of_chain_key = p.getBytes(64)
        self.signature = p.getBytes(64)
        assert(p.index == len(b)) # did we fully consume byte-array?
        
    def write(self):
        if self.sig_type not in TACK_Sig_Type.all:
            raise SyntaxError()
        w = Writer(169)
        w.add(self.sig_type, 1)
        w.add(self.sig_expiration, 4)
        w.add(self.sig_generation, 4)
        w.add(self.sig_target_sha256, 32)
        w.add(self.out_of_chain_key, 64)
        w.add(self.signature, 64)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?
        return w.bytes
        
        
class TACK_Pin_Break_Codes:
    def __init__(self):
        self.pin_break_codes = []
        
    def parse(self, b):
        p = Parser(b)
        self.pin_break_codes = p.getVarSeqBytes(24, 2)
        if len(self.pin_break_codes) < 1:
            raise SyntaxError()
        if len(self.pin_break_codes) > 100:
            raise SyntaxError()    
        assert(p.index == len(b)) # did we fully consume byte-array?
        
    def write(self):
        w = Writer(2 + 24*len(self.pin_break_codes))
        w.addVarSeq(self.pin_break_codes, 24, 2)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?        
        return w.bytes




################ SECRET FILE ###

import os, rijndael, ecdsa
from ecdsa import ellipticcurve

#  File format:
#
#  version        1  byte
#  iter_count     4 bytes
#  salt          16 bytes
#  IV            16 bytes         } auth
#    EC privkey  32 bytes  } enc  } auth
#    pin_break   24 bytes  } enc  } auth
#    zero_pad     8 bytes  } enc  } auth
#  EC pubkey     64 bytes         } auth
#  pin_break_sha256	32 bytes      } auth
#  HMAC          32 bytes	
# 
#  total		229

def xorbytes(s1, s2):
    return bytearray([a^b for a,b in zip(s1,s2)])

# Uses PBKDF2-HMAC-SHA256 to produce a 32-byte key
def pbkdf2_hmac_sha256(password, salt, iterations):
    m = salt + bytearray([0,0,0,1])
    result = bytearray(32)
    for c in range(iterations):
        m = HMAC_SHA256(password, m)
        result = xorbytes(m, result)
    return result

# Uses PBKDF2, then HMAC-SHA256 as PRF to derive independent 32-byte keys
def deriveSecretFileKeys(password, salt, iter_count):
    assert(iter_count>0)
    masterKey = pbkdf2_hmac_sha256(password, salt, iter_count)
    encKey = HMAC_SHA256(masterKey, bytearray([1]))
    authKey = HMAC_SHA256(masterKey, bytearray([2]))
    return (encKey, authKey)

def aes_cbc_decrypt(key, IV, ciphertext):
    cipher = rijndael.rijndael(str(key), 16)
    assert(len(ciphertext) % 16 == 0) # no padding
    chainBlock = IV
    plaintext = "" # not efficient, but doesn't matter here
    for c in range(len(ciphertext)/16):
        cipherBlock = ciphertext[c*16 : (c*16)+16]
        plaintext += xorbytes(bytearray(cipher.decrypt(str(cipherBlock))), chainBlock)
        chainBlock = cipherBlock
    return plaintext

def aes_cbc_encrypt(key, IV, plaintext):
    cipher = rijndael.rijndael(str(key), 16)
    assert(len(plaintext) % 16 == 0) # no padding
    chainBlock = IV
    ciphertext = "" # not efficient, but doesn't matter here
    for c in range(len(plaintext)/16):
        plainBlock = plaintext[c*16 : (c*16)+16]
        chainBlock = bytearray(cipher.encrypt(str(xorbytes(plainBlock, chainBlock))))
        ciphertext += chainBlock
    return ciphertext     
    
class TACK_SecretFile:
    def __init__(self):
        self.version = 0
        self.private_key = bytearray(32)
        self.out_of_chain_key = bytearray(64)
        self.pin_break_code = bytearray(24)
        self.pin_break_code_sha256 = bytearray(32)
        self.iter_count = 0
        
    def generate(self, extraRandBytes=None):
        self.version = 1        
        # ECDSA key generation per FIPS 186-3 B.4.1
        # (except we use 32 extra random bytes instead of 8 before reduction)
        # Random bytes taken from /dev/urandom as well as any extraRandBytes
        # REVIEW THIS CAREFULLY!!!  CHANGE AT YOUR PERIL!!!
        n = ecdsa.generator_256.order()
        randStr0_1 = bytearray(os.urandom(64))
        if extraRandBytes:
            randStr0_2 = bytearray(extraRandBytes)
        else:
            randStr0_2 = ""
        randStr0 = randStr0_1 + randStr0_2
        randStr1 = HMAC_SHA256(randStr0, bytearray([1]))
        randStr2 = HMAC_SHA256(randStr0, bytearray([2]))
        randStr3 = HMAC_SHA256(randStr0, bytearray([3]))
        randStr = randStr1 + randStr2    
        c = bytesToNumber(randStr) 
        d = (c % (n-1))+1        
        self.private_key = numberToBytes(d, 32)
        self.pin_break_code = randStr3[:24]
        public_key = ecdsa.generator_256 * d        
        self.out_of_chain_key = numberToBytes(public_key.x(), 32) + \
                                numberToBytes(public_key.y(), 32)
        self.pin_break_code_sha256 = SHA256(self.pin_break_code)
        self.iter_count = 8192

    def sign(self, hash):
        private_key = bytesToNumber(self.private_key)
        g = ecdsa.generator_256
        n = g.order()
        x = bytesToNumber(self.out_of_chain_key[:32])
        y = bytesToNumber(self.out_of_chain_key[32:])        
        pubkey = ecdsa.Public_key(g, ellipticcurve.Point(g.curve(), x,y))
        privkey = ecdsa.Private_key(pubkey, private_key)
        # Generating random nonce k per FIPS 186-3 B.5.1:
        # (except we use 32 extra bytes instead of 8 before reduction)
        # Random bytes taken from /dev/urandom as well as HMAC(privkey,hash)
        # REVIEW THIS CAREFULLY!!!  CHANGE AT YOUR PERIL!!!
        randStr0_1 = bytearray(os.urandom(64))
        randStr0_2 = HMAC_SHA256(self.private_key, hash)
        randStr0 = randStr0_1 + randStr0_2                    
        randStr1 = HMAC_SHA256(randStr0, bytearray([1]))
        randStr2 = HMAC_SHA256(randStr0, bytearray([2]))                       
        randStr = randStr1 + randStr2    
        c = bytesToNumber(randStr) 
        k = (c % (n-1))+1                
        hashNum = bytesToNumber(hash)
        sig = privkey.sign(hashNum, k)
        # Double-check before returning
        assert(pubkey.verifies(hashNum, sig))        
        return numberToBytes(sig.r, 32) + numberToBytes(sig.s, 32)

    def verify(self, hashVal):
        private_key = bytesToNumber(self.private_key)
        g = ecdsa.generator_256
        n = g.order()
        x = bytesToNumber(self.out_of_chain_key[:32])
        y = bytesToNumber(self.out_of_chain_key[32:])        
        pubkey = ecdsa.Public_key(g, ellipticcurve.Point(x,y))
        #!!! return pubkey.verifies(hashNum, sig))
        ##!!!

    def parse(self, b, password):
        p = Parser(b)
        self.version = p.getInt(1)
        if self.version != 1:
            raise SyntaxError()
        self.iter_count = p.getInt(4)
        salt = p.getBytes(16)
        IV = p.getBytes(16)
        ciphertext = p.getBytes(64)
        self.out_of_chain_key = p.getBytes(64)
        self.pin_break_code_sha256 = p.getBytes(32)
        mac = bytearray(p.getBytes(32))
        assert(p.index == len(b)) # did we fully consume byte-array?

        encKey, authKey = deriveSecretFileKeys(password, salt, self.iter_count)
        macData = IV + ciphertext + \
            self.out_of_chain_key + self.pin_break_code_sha256
        calcMac = HMAC_SHA256(authKey, macData)
        if not constTimeCompare(calcMac, mac):
            return False        
        plaintext = aes_cbc_decrypt(encKey, IV, ciphertext)
        self.private_key = plaintext[:32]
        self.pin_break_code = plaintext[32:56]
        return True
    
    def write(self, password):
        salt = bytearray(os.urandom(16))
        IV = bytearray(os.urandom(16))
        encKey, authKey = deriveSecretFileKeys(password, salt, self.iter_count)
        plaintext = self.private_key + self.pin_break_code + bytearray(8)
        ciphertext = aes_cbc_encrypt(encKey, IV, plaintext)
        macData = IV + ciphertext + \
            self.out_of_chain_key + self.pin_break_code_sha256
        mac = HMAC_SHA256(authKey, macData)        
        w = Writer(229)
        w.add(self.version, 1)
        w.add(self.iter_count, 4)
        w.add(salt, 16)
        w.add(IV, 16)
        w.add(ciphertext, 64)
        w.add(self.out_of_chain_key, 64)
        w.add(self.pin_break_code_sha256, 32)
        w.add(mac, 32)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?
        return w.bytes


################ TESTS ###


def testStructures():
    pin = TACK_Pin()
    sig = TACK_Sig()
    codes = TACK_Pin_Break_Codes()
    
    pin.pin_expiration = 12345;
    pin.pin_target_sha256 = bytearray(range(64,96))    
    pin.pin_break_code_sha256 = bytearray(range(32,64))    

    # Test reading/writing OOC pin
    pin.pin_type = TACK_Pin_Type.out_of_chain_key
    pin2 = TACK_Pin()
    pin2.parse(pin.write())
    assert(pin.write() == pin2.write())

    # Test reading/writing in-chain-key pin with pin-break        
    pin.pin_type = TACK_Pin_Type.in_chain_key
    pin2.parse(pin.write())
    assert(pin.write() == pin2.write())

    # Test reading/writing in-chain-cert pin with pin-break        
    pin.pin_type = TACK_Pin_Type.in_chain_cert
    pin2.parse(pin.write())
    assert(pin.write() == pin2.write())

    # Test reading/writing TACK_Sig
    sig.sig_type = TACK_Sig_Type.in_chain_cert
    sig.sig_expiration = 121
    sig.sig_generation = 3
    sig.sig_target_sha256 = bytearray(range(0, 32))
    sig.out_of_chain_key = bytearray(range(32, 96))
    sig.signature = bytearray(range(96, 160))
    sig2 = TACK_Sig()
    sig2.parse(sig.write())
    assert(sig.write() == sig2.write())

    # Test reading/writing TACK_Pin_Break_Codes with 1 code
    codes.pin_break_codes = [bytearray(range(0,24))]
    codes2 = TACK_Pin_Break_Codes()
    codes2.parse(codes.write())
    assert(codes.write() == codes2.write())

    # Test reading/writing TACK_Pin_Break_Codes with 3 code
    codes.pin_break_codes = [bytearray(range(0,24)),
                            bytearray(range(30, 54)),
                            bytearray(range(60, 84))]
    codes2 = TACK_Pin_Break_Codes()
    codes2.parse(codes.write())
    assert(codes.write() == codes2.write())

def testSecretFile():
    f = TACK_SecretFile()
    f.generate()
    
    b = f.write("abracadabra")
    f2 = TACK_SecretFile()
    assert(f2.parse(b, "abracadabra"))
    assert(f2.__dict__ == f.__dict__)

    f2.generate(bytearray("blablabla"))    
    h = bytearray(range(200, 232))
    sig = f2.sign(h)



################ MAIN ###

import sys, getpass, getopt

def printUsage(s):
    if s:
        print "ERROR: %s" % s
    print
    print"Commands:"
    print "  test"
    print "  pin <ssl_cert>"
    print
    sys.exit(-1)


def newSecretFile(extraRandStr=""):
    print "No secret file found, creating new one..."
    if not extraRandStr:
        while len(extraRandStr)<20:
            extraRandStr = getpass.getpass ("Enter at least 20 random keystrokes: ")    
    passwordStr = ""
    while not passwordStr:
        password1, password2 = "a", "b"
        while password1 != password2:
            password1 = getpass.getpass("Choose password for secret file: ")    
            password2 = getpass.getpass("Re-enter password for secret file: ")  
            if password1 != password2:
                print "PASSWORDS DON'T MATCH!"      
            else:
                passwordStr = password1    
    sf = TACK_SecretFile()
    sf.generate(extraRandStr)
    b = sf.write(passwordStr)
    f = open("__TACK_secret_file.dat", "wb")
    f.write(b)
    f.close()
    return sf

def openSecretFile(sfBytes):
    sf = TACK_SecretFile()
    while 1:
        password = getpass.getpass("Enter password for secret file: ")
        if sf.parse(sfBytes, password):
            break
        print "PASSWORD INCORRECT!"
    return sf
    
def newTACKCert(sf, sslBytes):    
    sigDays = pinDays = 550 # About 1.5 years
    currentTime = time.time()
    pinExp = currentTime + 1440 * pinDays
    sigExp = currentTime + 1440 * sigDays    
        
    pin = TACK_Pin()
    pin.pin_type = TACK_Pin_Type.out_of_chain_key
    pin.pin_expiration = pinExp
    pin.pin_target_sha256 = SHA256(sf.out_of_chain_key)
    pin.pin_break_code_sha256 = sf.pin_break_code_sha256
    
    sig = TACK_Sig()
    sig.sig_type = TACK_Sig_Type.in_chain_cert
    sig.sig_expiration = sigExp
    sig.sig_generation = 0
    sig.sig_target_sha256 = SHA256(sslBytes)
    sig.out_of_chain_key = sf.out_of_chain_key
    sig.signature = sf.sign(SHA256())
    
def updateTACKCert():
    pass

def pin(argv):
    if len(argv) != 1:
        printUsage("Missing argument: SSL certificate file")    
    try:
        sslBytes = bytearray(open(argv[0]).read())
    except IOError:
        printUsage("SSL certificate file not found: %s" % argv[0])
    try:
        tcBytes = bytearray(open("__TACK_cert.dat", "rb").read())
    except IOError:
        tcBytes = None
    try:    
        sfBytes = bytearray(open("__TACK_secret_file.dat", "rb").read())
    except IOError:
        sfBytes = None

    if not sfBytes:
        if not tcBytes:
            # No secret file or TACK cert, so generate new ones
            sf = newSecretFile()
            newTACKCert(sf, sslBytes)
        else:
            raise SyntaxError("Missing secret file")
    else:
        if not tcBytes:
            sf = openSecretFile(sfBytes)            
            newTACKCert(sf, sslBytes)
        else:
            sf = openSecretFile(sfBytes)                        
            updateTACKCert(sf, tcBytes, sslBytes)    
   

if __name__ == '__main__':
    if len(sys.argv) < 2:
        printUsage("Missing argument!")
    elif sys.argv[1] == "test":
        testStructures()
        testSecretFile()        
    elif sys.argv[1] == "pin":
        pin(sys.argv[2:])
    else:
        printUsage()



    

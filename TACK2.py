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


################ ECDSA ###

import ecdsa
from ecdsa import ellipticcurve

def ec256Generate(extraRandBytes=None):
    # ECDSA key generation per FIPS 186-3 B.4.1
    # (except we use 32 extra random bytes instead of 8 before reduction)
    # Random bytes taken from /dev/urandom as well as any extraRandBytes
    # REVIEW THIS CAREFULLY!  CHANGE AT YOUR PERIL!
    randStr0 = bytearray(os.urandom(64))
    if extraRandBytes:
        randStr0 += bytearray(extraRandBytes)
    randStr1 = HMAC_SHA256(randStr0, bytearray([1]))
    randStr2 = HMAC_SHA256(randStr0, bytearray([2]))
    randStr = randStr1 + randStr2    
    c = bytesToNumber(randStr) 
    n = ecdsa.generator_256.order()
    d = (c % (n-1))+1        
    privateKey = numberToBytes(d, 32)
    publicKeyPoint = ecdsa.generator_256 * d        
    publicKey = numberToBytes(publicKeyPoint.x(), 32) + \
                numberToBytes(publicKeyPoint.y(), 32)
    return (privateKey, publicKey)

def ecdsa256Sign(privateKey, publicKey, dataToSign):
    privateKeyNum = bytesToNumber(privateKey)
    hash = SHA256(dataToSign)
    g = ecdsa.generator_256
    n = g.order()
    x = bytesToNumber(publicKey[:32])
    y = bytesToNumber(publicKey[32:])        
    pubkey = ecdsa.Public_key(g, ellipticcurve.Point(g.curve(), x,y))    
    privkey = ecdsa.Private_key(pubkey, privateKeyNum)    

    # Generating random nonce k per FIPS 186-3 B.5.1:
    # (except we use 32 extra bytes instead of 8 before reduction)
    # Random bytes taken from /dev/urandom as well as HMAC(privkey,hash)
    # REVIEW THIS CAREFULLY!!!  CHANGE AT YOUR PERIL!!!
    randStr0_1 = bytearray(os.urandom(64))
    randStr0_2 = HMAC_SHA256(privateKey, hash)
    randStr0 = randStr0_1 + randStr0_2                    
    randStr1 = HMAC_SHA256(randStr0, bytearray([1]))
    randStr2 = HMAC_SHA256(randStr0, bytearray([2]))                       
    randStr = randStr1 + randStr2    
    c = bytesToNumber(randStr) 
    k = (c % (n-1))+1                
    hashNum = bytesToNumber(hash)
    sig = privkey.sign(hashNum, k)
    assert(pubkey.verifies(hashNum, sig))
    return numberToBytes(sig.r, 32) + numberToBytes(sig.s, 32)

def ecdsa256Verify(publicKey, dataToVerify, signature):
    hashNum = bytesToNumber(SHA256(dataToVerify))
    g = ecdsa.generator_256  
    x = bytesToNumber(publicKey[:32])
    y = bytesToNumber(publicKey[32:])        
    pubkey = ecdsa.Public_key(g, ellipticcurve.Point(g.curve(), x,y))
    sig = ecdsa.Signature(bytesToNumber(signature[:32]), 
                            bytesToNumber(signature[32:]))
    return pubkey.verifies(hashNum, sig)
    
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

import time, calendar

def posixTimeToStr(u, includeSeconds=False):    
    t = time.gmtime(u)
    if includeSeconds:
        s = time.strftime("%Y-%m-%dT%H:%M:%SZ", t)        
    else:
        s = time.strftime("%Y-%m-%dT%H:%MZ", t)
    return s
    
def getDefaultExpiration():
    days = pinDays = 550 # About 1.5 years
    currentTime = int(time.time()/60) # Get time in minutes
    exp = currentTime + (24*60) * days
    return exp

def parseTimeArg(arg):
    t = time.strptime(arg, "%Y-%m-%dT%H:%MZ")
    u = int(calendar.timegm(t)/60)
    return u
    

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


################ ASN1 PARSER ###
# Returns bytearray encoding an ASN1 length field
# Assumes maximum of 2-byte length
def asn1Length(x):
    if x < 128:
        return bytearray([x])
    if x < 256:
        return bytearray([0x81,x])  
    if x < 65536:
        return bytearray([0x82, int(x/256), x % 256])  
    assert(False)
    
#Takes a byte array which has a DER TLV field at its head
class ASN1Parser:
    def __init__(self, bytes, offset = 0):
        p = Parser(bytes)
        self.type = p.getInt(1) #skip Type

        #Get Length
        self.length = self._getASN1Length(p)
        
        # Header length is however many bytes read so far
        self.headerLength = p.index        

        #Get Value
        self.value = p.getBytes(self.length)
        
        # This value tracks the offset of this TLV field
        # in some enclosing structure (ie an X.509 cert) 
        self.offset = offset
        

    #Assuming this is a sequence...
    def getChild(self, which):
        p = Parser(self.value)
        for x in range(which+1):
            if p.index == len(p.bytes):
                return None
            markIndex = p.index
            p.getInt(1) #skip Type
            length = self._getASN1Length(p)
            p.getBytes(length)
        return ASN1Parser(p.bytes[markIndex : p.index], \
                            self.offset + self.headerLength + markIndex)

    #Assuming this is a tagged element...
    def getTagged(self):
        return ASN1Parser(self.value, self.offset + self.headerLength)

    def getTotalLength(self):
        return self.headerLength + self.length
        
    def getTotalBytes(self):
        return bytearray([self.type]) + asn1Length(self.length) + self.value

    #Decode the ASN.1 DER length field
    def _getASN1Length(self, p):
        firstLength = p.getInt(1)
        if firstLength<=127:
            lengthLength = 1
            return firstLength
        else:
            lengthLength = firstLength & 0x7F
            return p.getInt(lengthLength)
        

################ CONSTANTS ###

class TACK_Pin_Type:
    v1 = 1
    strings = (None, "v1")

class TACK_Sig_Type:
    v1_key = 1
    v1_cert = 2
    all = (v1_key, v1_cert)
    strings = (None, "v1_key", "v1_cert")
        

################ STRUCTURES ###

import binascii

def writeBytes(b):
    s = binascii.b2a_hex(b)
    retVal = ""
    while s:
        retVal += s[:32]
        s = s[32:]
        if len(s):
            retVal += "\n                           "
    return retVal
        
class TACK_Pin:
    length = 73
    
    def __init__(self):
        self.pin_type = 0
        self.pin_label = bytearray(8)
        self.pin_key = bytearray(64)
    
    def generate(self, pin_type, pin_label, pin_key):
        self.pin_type = pin_type
        self.pin_label = pin_label
        self.pin_key = pin_key
            
    def parse(self, b):
        p = Parser(b)
        self.pin_type = p.getInt(1)
        if self.pin_type != TACK_Pin_Type.v1:
            raise SyntaxError()
        self.pin_label = p.getBytes(8)
        self.pin_key = p.getBytes(64)
        assert(p.index == len(b)) # did we fully consume byte-array?
        
    def write(self):        
        if self.pin_type != TACK_Pin_Type.v1:
            raise SyntaxError()        
        w = Writer(TACK_Pin.length)
        w.add(self.pin_type, 1)
        w.add(self.pin_label, 8)  
        w.add(self.pin_key, 64)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?            
        return w.bytes  

    def writeText(self):
        if self.pin_type != TACK_Pin_Type.v1:
            raise SyntaxError()
        s = \
"""pin_type               = %s
pin_label              = 0x%s
pin_key                = 0x%s\n""" % \
(TACK_Pin_Type.strings[self.pin_type], 
writeBytes(self.pin_label),
writeBytes(self.pin_key))
        return s
        
           
class TACK_Sig:
    length = 105
        
    def __init__(self):
        self.sig_type = 0
        self.sig_expiration = 0
        self.sig_revocation = 0                
        self.sig_target_sha256 = bytearray(32)
        self.signature = bytearray(64)
        
    def generate(self, sig_type, sig_expiration, sig_revocation,
                sig_target_sha256, pin, signFunc):
        self.sig_type = sig_type
        self.sig_expiration = sig_expiration
        self.sig_revocation = sig_revocation                
        self.sig_target_sha256 = sig_target_sha256
        self.signature = signFunc(pin.write() + self.write()[:-64])
    
    def parse(self, b):
        p = Parser(b)
        self.sig_type = p.getInt(1)
        if self.sig_type not in TACK_Sig_Type.all:
            raise SyntaxError()
        self.sig_expiration = p.getInt(4)
        self.sig_revocation = p.getInt(4)            
        self.sig_target_sha256 = p.getBytes(32)
        self.signature = p.getBytes(64)
        assert(p.index == len(b)) # did we fully consume byte-array?
        
    def write(self):
        if self.sig_type not in TACK_Sig_Type.all:
            raise SyntaxError()
        w = Writer(TACK_Sig.length)
        w.add(self.sig_type, 1)
        w.add(self.sig_expiration, 4)
        w.add(self.sig_revocation, 4)
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
sig_revocation         = %s
sig_target_sha256      = 0x%s
signature              = 0x%s\n""" % \
(TACK_Sig_Type.strings[self.sig_type], 
posixTimeToStr(self.sig_expiration*60),
posixTimeToStr(self.sig_revocation*60),
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

    def writeText(self):
        s = \
"""break_label            = 0x%s
break_signature        = 0x%s\n""" % \
(writeBytes(self.pin_label), 
 writeBytes(self.signature))
        return s


class TACK_Break_Sigs:
    def __init__(self):
        self.break_sigs = []
    
    def add(self, break_sig):
        assert(len(self.break_sigs) < 20)
        assert(isinstance(break_sig, TACK_Break_Sig))
        self.break_sigs.append(break_sig)
    
    def parse(self, b):
        p = Parser(b)
        numBreakSigs = int(p.getInt(2) / TACK_Break_Sig.length)
        if numBreakSigs>20:
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
        return "".join(b.writeText() for b in self.break_sigs)


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

################ SSL CERT ###

def dePemCert(s):
    start = s.find("-----BEGIN CERTIFICATE-----")
    end = s.find("-----END CERTIFICATE-----")
    if start == -1:
        raise SyntaxError("Missing PEM prefix")
    if end == -1:
        raise SyntaxError("Missing PEM postfix")
    s = s[start+len("-----BEGIN CERTIFICATE-----") : end]
    return bytearray(binascii.a2b_base64(s))

def pemCert(b):
    s1 = binascii.b2a_base64(b)[:-1] # remove terminating \n
    s2 = ""
    while s1:
        s2 += s1[:64] + "\n"
        s1 = s1[64:]
    return "-----BEGIN CERTIFICATE-----\n" + s2 + \
            "-----END CERTIFICATE-----"     
        
class SSL_Cert:
    def __init__(self):
        self.key_sha256 = bytearray(32)
        self.cert_sha256 = bytearray(32)
    
    def parse(self, b):
        try:
            b = dePemCert(b)
        except SyntaxError:
            pass
        p = ASN1Parser(b)

        #Get the tbsCertificate
        tbsCertificateP = p.getChild(0)

        #Is the optional version field present?
        #This determines which index the key is at
        if tbsCertificateP.value[0]==0xA0:
            subjectPublicKeyInfoIndex = 6
        else:
            subjectPublicKeyInfoIndex = 5             
        #Get the subjectPublicKeyInfo
        spkiP = tbsCertificateP.getChild(\
                                    subjectPublicKeyInfoIndex)
        self.cert_sha256 = SHA256(b)
        self.key_sha256 = SHA256(spkiP.getTotalBytes())
    
    def writeText(self):
        s = \
"""key_sha256             = 0x%s
cert_sha256            = 0x%s\n""" % (\
        writeBytes(self.key_sha256),
        writeBytes(self.cert_sha256))
        return s
        

################ TACK CERT ###

class TACK_Cert:
    oid_TACK = bytearray("\x2B\x06\x01\x04\x01\x82\xB0\x34\x01")
    oid_TACK_Break_Sigs = bytearray("\x2B\x06\x01\x04\x01\x82\xB0\x34\x02")
    
    def __init__(self):
        self.TACK = None
        self.break_sigs = None
        self.preExtBytes = None 
        self.extBytes = None
        self.postExtBytes = None
    
    def generate(self, pin=None, sig=None, break_sigs=None):
        self.TACK = None
        self.break_sigs = None
        self.preExtBytes = binascii.a2b_hex(\
"a003020102020100300d06092a864886f70d0101050500300f310d300b06035504031"
"3045441434b301e170d3031303730353138303534385a170d33343037303431383035"
"34385a300f310d300b060355040313045441434b301f300d06092a864886f70d01010"
"10500030e00300b0204010203040203010001")
        # Below is BasicConstraints, saving space by omitting
        #self.extBytes = binascii.a2b_hex(\
#"300c0603551d13040530030101ff")
        self.extBytes = bytearray()
        self.postExtBytes = binascii.a2b_hex(\
"300d06092a864886f70d01010505000303003993")
    
    def parse(self, b):
        try:
            b = dePemCert(b)
        except SyntaxError:
            pass        
        p = ASN1Parser(b)
        self.extBytes = bytearray()

        # We are going to copy the non-TACK chunks of cert into here
        # Thus, when we go to write it out, we just have to inject
        # the TACK chunks and adjust a few length fields
        self.bytes = bytearray(0)
        copyFromOffset = 0

        #Get the tbsCertificate
        tbsCertificateP = p.getChild(0)
        versionP = tbsCertificateP.getChild(0)        
        if versionP.type != 0xA0: # i.e. tag of [0], version
            raise SyntaxError("X.509 version field not present")
        versionPP = versionP.getTagged()
        if versionPP.value != bytearray([0x02]):
            raise SyntaxError("X.509 version field does not equal v3")

        # Find extensions element
        x = 0
        while 1:
            certFieldP = tbsCertificateP.getChild(x)
            if not certFieldP:
                raise SyntaxError("X.509 extensions not present")
            if certFieldP.type == 0xA3: # i.e. tag of [3], extensions
                break
            x += 1

        self.preExtBytes = b[versionP.offset : certFieldP.offset]
        self.extBytes = bytearray()

        # Iterate through extensions
        x = 0
        certFieldPP = certFieldP.getTagged()
        while 1:
            extFieldP = certFieldPP.getChild(x)
            if not extFieldP:
                break
                    
            # Check the extnID and parse out TACK structure if present
            extnIDP = extFieldP.getChild(0)            
            if extnIDP.value == TACK_Cert.oid_TACK:
                if self.TACK:
                    raise SyntaxError("More than one TACK structure")                
                self.TACK = TACK()
                self.TACK.parse(extFieldP.getChild(1).value)                    
            elif extnIDP.value == TACK_Cert.oid_TACK_Break_Sigs:
                if self.break_sigs:
                    raise SyntaxError("More than one TACK_Break_Sigs")                
                self.break_sigs = TACK_Break_Sigs()
                self.break_sigs.parse(extFieldP.getChild(1).value)                    
            else:  
                # Collect all non-TACK extensions:
                self.extBytes += b[extFieldP.offset : \
                                    extFieldP.offset + extFieldP.getTotalLength()]
            x += 1                

        # Finish copying the tail of the certificate
        self.postExtBytes = b[certFieldP.offset + certFieldP.getTotalLength() : ]
        
    def write(self):        
        b = bytearray(0)
        if self.TACK:
            # type=SEQ,len=?,type=6,len=9(for OID),
            # type=4,len=?,TACK
            TACKBytes = self.TACK.write()            
            b = bytearray([4]) + asn1Length(len(TACKBytes)) + TACKBytes
            b = bytearray([6,9]) + self.oid_TACK + b
            b = bytearray([0x30]) + asn1Length(len(b)) + b
        if self.break_sigs:
            breakBytes = self.break_sigs.write()
            b2 = bytearray([4]) + asn1Length(len(breakBytes)) + breakBytes
            b2 = bytearray([6,9]) + self.oid_TACK_Break_Sigs + b2
            b2 = bytearray([0x30]) + asn1Length(len(b2)) + b2
            b += b2
        
        b = b + self.extBytes # add non-TACK extensions after TACK
        # Add length fields for extensions and its enclosing tag
        b = bytearray([0x30]) + asn1Length(len(b)) + b
        b = bytearray([0xA3]) + asn1Length(len(b)) + b
        # Add prefix of tbsCertificate, then its type/length fields
        b = self.preExtBytes + b
        b = bytearray([0x30]) + asn1Length(len(b)) + b
        # Add postfix of Certificate (ie SignatureAlgorithm, SignatureValue)
        # then its prefix'd type/length fields
        b = b + self.postExtBytes
        b = bytearray([0x30]) + asn1Length(len(b)) + b
        return b

    def writeText(self):
        s = ""
        if self.TACK:
            s += self.TACK.writeText()
        if self.break_sigs:
            s += self.break_sigs.writeText()
        if not s:
            return "No TACK structures\n"
        else:
            return s


################ SECRET FILE ###

import os, rijndael
#  File format:
#
#  magic number   3 bytes = 0x9a6127
#  version        1  byte
#  iter_count     4 bytes
#  salt          16 bytes
#  IV            16 bytes         } auth
#    EC privkey  32 bytes  } enc  } auth
#  EC pubkey     64 bytes         } auth
#  HMAC          32 bytes	
# 
#  total		168

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
def deriveKeyFileKeys(password, salt, iter_count):
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

class TACK_KeyFileViewer:
    def __init__(self):
        self.version = 0
        self.iter_count = 0
        self.salt = bytearray(16)
        self.IV = bytearray(16)
        self.ciphertext = bytearray(64)
        self.public_key = bytearray(64)
        self.mac = bytearray(32)
        
    def parse(self, b):
        p = Parser(b)
        magic = p.getBytes(3)
        if magic != TACK_KeyFile.magic:
            raise SyntaxError("Bad magic number in Secret File")
        self.version = p.getInt(1)
        if self.version != 1:
            raise SyntaxError("Bad version in Secret File")
        self.iter_count = p.getInt(4)
        self.salt = p.getBytes(16)
        self.IV = p.getBytes(16)
        self.ciphertext = p.getBytes(32)
        self.public_key = p.getBytes(64)
        self.mac = bytearray(p.getBytes(32))
        assert(p.index == len(b)) # did we fully consume byte-array?

    def writeText(self):
        s = \
"""version                = %d
iter_count             = %d
salt                   = 0x%s
IV                     = 0x%s
ciphertext             = 0x%s
public_key             = 0x%s
mac                    = 0x%s\n""" % \
        (self.version, 
        self.iter_count,
        writeBytes(self.salt),
        writeBytes(self.IV),
        writeBytes(self.ciphertext),
        writeBytes(self.public_key),
        writeBytes(self.mac))
        return s        
        
    
class TACK_KeyFile:
    magic = bytearray([0x9A,0x61,0x27])

    def __init__(self):
        self.version = 0
        self.private_key = bytearray(32)
        self.public_key = bytearray(64)
        self.iter_count = 0
        
    def generate(self, extraRandBytes=None):
        self.version = 1
        self.private_key, self.public_key = ec256Generate(extraRandBytes)
        self.iter_count = 8192

    def sign(self, bytesToSign):
        signature = ecdsa256Sign(self.private_key, self.public_key, bytesToSign)
        # Double-check value before returning
        assert(ecdsa256Verify(self.public_key, bytesToSign, signature))
        return signature

    def parse(self, b, password):
        p = Parser(b)
        magic = p.getBytes(3)
        if magic != TACK_KeyFile.magic:
            raise SyntaxError("Bad magic number in Secret File")
        self.version = p.getInt(1)
        if self.version != 1:
            raise SyntaxError("Bad version in Secret File")
        self.iter_count = p.getInt(4)
        salt = p.getBytes(16)
        IV = p.getBytes(16)
        ciphertext = p.getBytes(32)
        self.public_key = p.getBytes(64)
        mac = bytearray(p.getBytes(32))
        assert(p.index == len(b)) # did we fully consume byte-array?

        encKey, authKey = deriveKeyFileKeys(password, salt, self.iter_count)
        macData = IV + ciphertext + self.public_key
        calcMac = HMAC_SHA256(authKey, macData)
        if not constTimeCompare(calcMac, mac):
            return False        
        plaintext = aes_cbc_decrypt(encKey, IV, ciphertext)
        self.private_key = plaintext
        return True
    
    def write(self, password):
        salt = bytearray(os.urandom(16))
        IV = bytearray(os.urandom(16))
        encKey, authKey = deriveKeyFileKeys(password, salt, self.iter_count)
        plaintext = self.private_key
        ciphertext = aes_cbc_encrypt(encKey, IV, plaintext)
        macData = IV + ciphertext + self.public_key
        mac = HMAC_SHA256(authKey, macData)        
        w = Writer(168)
        w.add(TACK_KeyFile.magic, 3)
        w.add(self.version, 1)
        w.add(self.iter_count, 4)
        w.add(salt, 16)
        w.add(IV, 16)
        w.add(ciphertext, 32)
        w.add(self.public_key, 64)
        w.add(mac, 32)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?
        return w.bytes


################ TESTS ###


def testStructures():
    pin = TACK_Pin()
    sig = TACK_Sig()
    
    pin.generate(TACK_Pin_Type.v1, os.urandom(8), os.urandom(64))

    # Test reading/writing OOC pin
    pin2 = TACK_Pin()
    pin2.parse(pin.write())
    assert(pin.write() == pin2.write())


    # Test reading/writing TACK_Sig
    privKey, pubKey = ec256Generate()
    sig.generate(TACK_Sig_Type.v1_cert,
                 100000, 200000, os.urandom(32), pin,
                 lambda(b):ecdsa256Sign(privKey, pubKey, b))
    sig2 = TACK_Sig()
    sig2.parse(sig.write())
    assert(sig.write() == sig2.write())
    #print "\nTACK_Sig:\n", sig2.writeText()

    # Test reading/writing TACK_Break_Sigs with 1 code
    break_sig = TACK_Break_Sig()
    break_sig.pin_label = os.urandom(8)
    break_sig.signature = os.urandom(64)
    break_sig2 = TACK_Break_Sig()
    break_sig2.parse(break_sig.write())
    assert(break_sig.write() == break_sig2.write())
        

def testKeyFile():
    f = TACK_KeyFile()
    f.generate()
    
    b = f.write("abracadabra")
    f2 = TACK_KeyFile()
    assert(f2.parse(b, "abracadabra"))
    assert(f2.__dict__ == f.__dict__)

    f2.generate(bytearray("blablabla"))    
    h = bytearray(range(100,200))
    sig = f2.sign(h)

def testCert():
    sigDays = pinDays = 550 # About 1.5 years
    currentTime = int(time.time()/60) # Get time in minutes
    sigExp = currentTime + (24*60) * sigDays    
    
    sslBytes = bytearray(range(1,200))
    kf = TACK_KeyFile()
    kf.generate()    
        
    pin = TACK_Pin()
    pin.generate(TACK_Pin_Type.v1, os.urandom(8), kf.public_key)
        
    privKey, pubKey = ec256Generate()
    sig = TACK_Sig()
    sig.generate(TACK_Sig_Type.v1_cert,
                 sigExp, sigExp+100, 
                 SHA256(sslBytes), pin,
                 lambda(b):ecdsa256Sign(privKey,pubKey,b))
                     
    tc = TACK_Cert()
    tc.generate(pin, sig)

    tc2 = TACK_Cert()
    tc2.parse(tc.write())
    assert(tc.write() == tc2.write())

################ MAIN ###

import sys, getpass, getopt, glob

def printUsage(s=None):
    if s:
        print "ERROR: %s" % s
    print
    print"Commands:"
    print "  new    <ssl_cert>"
    print "  update <ssl_cert>"
    print "  break"
    print "  view   <file or site>"
    print
    sys.exit(-1)

def printError(s):
    print "ERROR: %s\n" % s
    sys.exit(-1)

def newKeyFile(extraRandStr=""):
    if not extraRandStr:
        while len(extraRandStr)<20:
            extraRandStr = getpass.getpass ("Enter at least 20 random keystrokes: ")    
    kf = TACK_KeyFile()
    kf.generate(extraRandStr)
    return kf

def openKeyFile(kfBytes):
    kf = TACK_KeyFile()
    while 1:
        password = getpass.getpass("Enter password for key file: ")
        if kf.parse(kfBytes, password):
            break
        print "PASSWORD INCORRECT!"
    return kf

def createFileRaiseOSExIfExists(name):
    fd = os.open(name, os.O_EXCL | os.O_CREAT | os.O_WRONLY)
    f = os.fdopen(fd, "wb")
    return f    

def writeKeyFile(kf, suffix):
    passwordStr = ""
    while not passwordStr:
        password1, password2 = "a", "b"
        while password1 != password2:
            password1 = getpass.getpass("Choose password for key file: ")    
            password2 = getpass.getpass("Re-enter password for key file: ")  
            if password1 != password2:
                print "PASSWORDS DON'T MATCH!"      
            else:
                passwordStr = password1    
    b = kf.write(passwordStr)
    f = open("__TACK_key_%s.dat" % suffix, "wb")
    f.write(b)
    f.close()
    return kf    

def writeTACKCert(tc, oldName, suffix, noPem=False, noBackup=False):    
    b = tc.write()
    if not noPem:
        newExt = "pem"
        b = pemCert(b)
    else:
        newExt = "der"       
        
    # Backup old TACK cert (if there is one)
    if oldName:
        oldf = open(oldName, "rb")
        oldBytes = oldf.read()
        oldf.close()
        bakName = "__OLD" + oldName[1:] # chopp off first underscore
        try:
            bakf = createFileRaiseOSExIfExists(bakName)
        except OSError:
            printError(
"Can't back up %s as its backup already exists?!" % bakName) 
        bakf.write(oldBytes)
        bakf.close()
        os.remove(oldName)
    
    # Create the new filename, ensure it get a name later than
    # the file it is replacing.  Sleeping is a little hokey, maybe
    # it would be better to append something to the filenames?
    while 1: 
        newName = "__TACK_cert_%s_%s.%s" % \
            (suffix, posixTimeToStr(time.time(), True), newExt)
        if oldName and newName[:-3] == oldName[:-3]: #compare except extensions
            time.sleep(0.5)
        else:
            break

    newf = open(newName, "wb")
    newf.write(b)
    newf.close()

def openTACKFiles(errorNoCertOrKey=False):       
    tcGlobPem = glob.glob("__TACK_cert_*_*.pem")
    tcGlobDer = glob.glob("__TACK_cert_*_*.der")
    tcGlob = tcGlobPem + tcGlobDer
    if len(tcGlob) == 0:
        if errorNoCertOrKey:
            printError("No TACK cert found")
        tcBytes = None
        tcName = None
        suffix = None
    elif len(tcGlob) > 1:
        printError("More than one TACK cert found")
    else:
        tcName = tcGlob[0]
        lIndex = len("__TACK_cert_")
        rIndex = tcName.find("_", lIndex)        
        suffix = tcName[lIndex : rIndex]
        tcBytes = bytearray(open(tcName, "rb").read())

    kfGlob = glob.glob("__TACK_key_*.dat")
    if len(kfGlob) == 0:
        if errorNoCertOrKey:
            printError("No TACK key found")
        kfBytes = None
    elif len(kfGlob) > 1:
        printError("More than one TACK key found")
    else:
        kfName = kfGlob[0]
        kfBytes = bytearray(open(kfName, "rb").read())        

    tc = TACK_Cert()
    if tcBytes:
        print "Updating %s..." % tcName
        try:
            tc.parse(tcBytes)
        except SyntaxError:
            printError("TACK certificate malformed: %s" % tcName)
    else:
        tc.generate()
        print "No TACK certificate found, creating new one..."

    if kfBytes:
        print "Opening %s..." % kfName        
        try:
            kf = openKeyFile(kfBytes)   
        except SyntaxError:
            printError("%s malformed" % kfName)        
    else:
        kf = None
    return (tc, kf, suffix, tcName)

def confirmY(s):
    query = raw_input(s)
    if query != "y":
        printError("Cancelled")    
    
def pin(argv, update=False):
    # Collect cmdline args into a dictionary
    if len(argv) < 1:
        printError("Missing argument: SSL certificate file")    
    noArgArgs = ["--no_pem"]
    oneArgArgs= ["--sig_type", "--sig_expiration", "--sig_revocation"]

    sslName = argv[0]
    argsDict = {}    
    for arg in argv[1:]:
        parts = arg.split("=")
        if parts[0] in argsDict:
            printError("Duplicate argument: %s" % parts[0])
        if len(parts)==2:
            if not parts[0] in oneArgArgs:
                printError("Unknown or malformed argument: %s" % parts[0])
            argsDict[parts[0]] = parts[1]
        elif len(parts)==1:
            if not parts[0] in noArgArgs:
                printError("Unknown or malformed argument: %s" % parts[0])            
            argsDict[parts[0]] = None
        else:
            printError("Unknown or malformed argument: %s" % parts[0])

    # Process the cmdline dictionary
    noPem = False
    sig_type = TACK_Sig_Type.v1_cert
    defaultExpiration = getDefaultExpiration()
    sig_expiration = defaultExpiration
    sig_revocation = defaultExpiration

    if "--no_pem" in argsDict:
        noPem = True   
    if "--sig_type" in argsDict:    
        val = argsDict["--sig_type"]
        if val == "v1_key":
            sig_type = TACK_Sig_Type.v1_key
        elif val == "v1_cert":
            sig_type = TACK_Sig_Type.v1_cert
        else:
            printError("Unrecognized sig_type")
    if "--sig_expiration" in argsDict:
        sig_expiration = parseTimeArg(argsDict["--sig_expiration"])
    if "--sig_revocation" in argsDict:
        sig_revocation = parseTimeArg(argsDict["--sig_revocation"])
    
    # Open the SSL cert
    try:
        sslBytes = bytearray(open(sslName).read())
    except IOError:
        printError("SSL certificate file not found: %s" % argv[0])
    sslc = SSL_Cert()
    try:
        sslc.parse(sslBytes)        
    except SyntaxError:
        prinError("SSL certificate malformed: %s" % argv[0])
    
    # Open the __TACK_cert and __TACK_key files, creating latter if needed
    tc, kf, suffix, tcName = openTACKFiles(update)
    if not kf:
        print "No TACK key found, creating new one..."
        kf = newKeyFile()
        mustWriteKeyFile = True
    else:
        mustWriteKeyFile = False        

    # Check existing TACK_Pin and TACK_Sig
    if update:
        if not tc.TACK:
            printError("TACK certificate has no TACK extension")
        tc.TACK.sig = None
    elif not update and tc.TACK:
        confirmY('There is an existing TACK, choose "y" to replace: ')        
        tc.TACK = None

    # Prompt for suffix
    if not update:
        if mustWriteKeyFile:
            suffix = raw_input(
"Enter a short suffix for your TACK key and cert files: ")
        else:
            suffix = raw_input(
"Enter a short suffix for your TACK cert file: ")

    # Produce the TACK_Pin (if "new")
    if not update:
        tc.TACK = TACK()
        tc.TACK.pin = TACK_Pin()            
        label = bytearray(os.urandom(8))
        tc.TACK.pin.generate(TACK_Pin_Type.v1, label, kf.public_key)

    # Produce the TACK_Sig
    if sig_type == TACK_Sig_Type.v1_key:
        sig_target_sha256 = sslc.key_sha256
    elif sig_type == TACK_Sig_Type.v1_cert:
        sig_target_sha256 = sslc.cert_sha256
    tc.TACK.sig = TACK_Sig()
    tc.TACK.sig.generate(sig_type, sig_expiration, sig_revocation, 
                    sig_target_sha256, tc.TACK.pin, kf.sign)

    # Write out files
    writeTACKCert(tc, tcName, suffix, noPem)
    if mustWriteKeyFile:
        writeKeyFile(kf, suffix)

def promptForPinLabel():
    while 1:
        labelStr = raw_input("Enter pin_label to break: ").lower()
        if labelStr.startswith("0x"):
            labelStr = labelStr[2:]
        try:
            pin_label = binascii.a2b_hex(labelStr)
            break
        except TypeError:
            pass
    return pin_label

def breakPin(argv):
    noPem = True
    tc, kf, suffix, tcName = openTACKFiles(True)
    if not tc.break_sigs:
        tc.break_sigs = TACK_Break_Sigs()
    break_sig = TACK_Break_Sig()
    

    if not tc.TACK:
        print "WARNING: There is no existing TACK..."
        pin_label = promptForPinLabel()
        print "Breaking pin_label = 0x%s" % binascii.b2a_hex(pin_label)        
    elif tc.TACK.pin.pin_key != kf.public_key:
        print "WARNING: This key DOES NOT MATCH the existing TACK..."
        pin_label = promptForPinLabel()
        print "Breaking pin_label = 0x%s" % binascii.b2a_hex(pin_label)        
    else:
        pin_label = tc.TACK.pin.pin_label
        print "Breaking existing TACK, pin_label = 0x%s" % binascii.b2a_hex(pin_label)
    confirmY('Is this correct? ("y" to continue): ')            
    
    break_sig.generate(pin_label, kf.sign(pin_label))
    tc.break_sigs.add(break_sig)
    
    # If we broke the existing TACK pin, remove it
    if tc.TACK and pin_label == tc.TACK.pin.pin_label and \
            kf.public_key == tc.TACK.pin.pin_key:
        tc.TACK = None
    
    writeTACKCert(tc, tcName, suffix, noPem)
     
def view(argv):
    if len(argv) < 1:
        printError("Missing argument: object to view")
    if len(argv) > 1:
        printError("Can only view one object")
    try:
        b = bytearray(open(argv[0]).read())
    except IOError:
        printError("File not found: %s" % argv[0])
    # If it's a key file
    if len(b) == 168 and b[:3] == TACK_KeyFile.magic:
        kfv = TACK_KeyFileViewer()
        kfv.parse(b)
        print kfv.writeText()
    # If not it could be a certificate
    else: 
        try:
            written=0            
            tc = TACK_Cert()
            tc.parse(b)
            if tc.TACK or tc.break_sigs:
                print tc.writeText()
                written = 1      
        except SyntaxError:
            pass
        if not written:
            try:
                sslc = SSL_Cert()
                sslc.parse(b)
                print sslc.writeText()      
            except SyntaxError:
                printError("Unrecognized file type")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        printUsage("Missing command")
    elif sys.argv[1] == "test":
        testCert()
        testStructures()
        testKeyFile()        
    elif sys.argv[1] == "new":
        pin(sys.argv[2:], False)
    elif sys.argv[1] == "update":
        pin(sys.argv[2:], True)
    elif sys.argv[1] == "break":
        breakPin(sys.argv[2:])
    elif sys.argv[1] == "view":
        view(sys.argv[2:])
    else:
        printUsage("Unknown command: %s" % sys.argv[1])



    

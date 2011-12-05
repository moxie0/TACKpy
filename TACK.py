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

import time, calendar

def timeUintToStr(u):    
    t = time.gmtime(60*u)
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
    in_chain_key = 1
    in_chain_cert = 2    
    out_of_chain_key = 3
    all = (in_chain_key, in_chain_cert, out_of_chain_key)
    strings = (None, "in_chain_key", "in_chain_cert", "out_of_chain_key")

class TACK_Sig_Type:
    in_chain_key = 1
    in_chain_cert = 2
    all = (in_chain_key, in_chain_cert)
    strings = (None, "in_chain_key", "in_chain_cert")
        

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
    def __init__(self):
        self.pin_type = 0
        self.pin_expiration = 0
        self.pin_target_sha256 = bytearray(32)
        self.pin_break_code_sha256 = bytearray(32)
        
    def isExpired(self):
        return self.pin_expiration*60 < time.time()         
    
    def generate(self, pin_type, pin_expiration, 
                pin_target_sha256, pin_break_code_sha256):
        self.pin_type = pin_type
        self.pin_expiration = pin_expiration
        self.pin_target_sha256 = pin_target_sha256
        self.pin_break_code_sha256 = pin_break_code_sha256        
            
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

    def writeText(self):
        if self.pin_type not in TACK_Pin_Type.all:
            raise SyntaxError()
        s = \
"""pin_type               = %s
pin_expiration         = %s
pin_target_sha256      = 0x%s
pin_break_code_sha256  = 0x%s""" % \
(TACK_Pin_Type.strings[self.pin_type], 
timeUintToStr(self.pin_expiration),
writeBytes(self.pin_target_sha256),
writeBytes(self.pin_break_code_sha256))
        return "TACK_Pin:\n"+s
        
           
class TACK_Sig:    
    def __init__(self):
        self.sig_type = 0
        self.sig_expiration = 0
        self.sig_revocation = 0                
        self.sig_target_sha256 = bytearray(32)
        self.out_of_chain_key = bytearray(64)
        self.signature = bytearray(64)
        
    def generate(self, sig_type, sig_expiration, sig_revocation,
                sig_target_sha256, out_of_chain_key, sigFunc):
        self.sig_type = sig_type
        self.sig_expiration = sig_expiration
        self.sig_revocation = sig_revocation                
        self.sig_target_sha256 = sig_target_sha256
        self.out_of_chain_key = out_of_chain_key
        self.signature = sigFunc(self.write()[:-64])
    
    def parse(self, b):
        p = Parser(b)
        self.sig_type = p.getInt(1)
        if self.sig_type not in TACK_Sig_Type.all:
            raise SyntaxError()
        self.sig_expiration = p.getInt(4)
        self.sig_revocation = p.getInt(4)            
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
        w.add(self.sig_revocation, 4)
        w.add(self.sig_target_sha256, 32)
        w.add(self.out_of_chain_key, 64)
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
out_of_chain_key       = 0x%s
signature              = 0x%s""" % \
(TACK_Sig_Type.strings[self.sig_type], 
timeUintToStr(self.sig_expiration),
timeUintToStr(self.sig_revocation),
writeBytes(self.sig_target_sha256),
writeBytes(self.out_of_chain_key),
writeBytes(self.signature))
        return "TACK_Sig:\n"+s

        
        
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

    def writeText(self):
        s = "count                  = %d\n" % len(self.pin_break_codes)
        enumeration = enumerate(self.pin_break_codes)
        formatted = [(i, binascii.b2a_hex(c)) for (i,c) in enumeration]
        codes = ["pin_break_code[%d]      = %s" % (i,c) for (i,c) in formatted]
        s += "\n".join(codes)
        return "TACK_Pin_Break_Codes:\n"+s


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
        self.in_chain_key_sha256 = bytearray(32)
        self.in_chain_cert_sha256 = bytearray(32)
    
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
        self.in_chain_cert_sha256 = SHA256(b)
        self.in_chain_key_sha256 = SHA256(spkiP.getTotalBytes())
    
    def writeText(self):
        s = \
"""in_chain_key_sha256    = 0x%s
in_chain_cert_sha256   = 0x%s""" % (\
        writeBytes(self.in_chain_key_sha256),
        writeBytes(self.in_chain_cert_sha256))
        return "SSL Certificate:\n" + s
        

################ TACK CERT ###

class TACK_Cert:
    oid_pin = bytearray("\x2B\x06\x01\x04\x01\x82\xB0\x34\x01")
    oid_sig = bytearray("\x2B\x06\x01\x04\x01\x82\xB0\x34\x02")
    oid_codes = bytearray("\x2B\x06\x01\x04\x01\x82\xB0\x34\x03")
    oid_all = (oid_pin, oid_sig, oid_codes)
    
    def __init__(self):
        self.pin = None # TACK_Pin
        self.sig = None # TACK_Sig
        self.codes = None # TACK_Pin_Break_Codes
        self.preExtBytes = None 
        self.extBytes = None
        self.postExtBytes = None
    
    def generate(self, pin=None, sig=None, codes=None):
        self.pin = pin
        self.sig = sig
        self.codes = codes
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
                    
            # Check the extnID and parse out TACK structures if present
            extnIDP = extFieldP.getChild(0)            
            if extnIDP.value == TACK_Cert.oid_pin:
                if self.pin:
                    raise SyntaxError("More than one TACK_Pin extension")
                self.pin = TACK_Pin()
                self.pin.parse(extFieldP.getChild(1).value)
            elif extnIDP.value == TACK_Cert.oid_sig:
                if self.sig:
                    raise SyntaxError("More than one TACK_Sig extension")                
                self.sig = TACK_Sig()
                self.sig.parse(extFieldP.getChild(1).value)                
            elif extnIDP.value == TACK_Cert.oid_codes:
                if self.codes:
                    raise SyntaxError("More than one TACK_Pin_Break_Codes extension")                
                self.codes = TACK_Pin_Break_Codes()
                self.codes.parse(extFieldP.getChild(1).value)
            else:  
                # Collect all non-TACK extensions:
                self.extBytes += b[extFieldP.offset : \
                                    extFieldP.offset + extFieldP.getTotalLength()]
            x += 1                

        # Finish copying the tail of the certificate
        self.postExtBytes = b[certFieldP.offset + certFieldP.getTotalLength() : ]
        
        # Check consistency between TACK_Pin and TACK_Sig
        if self.sig and self.pin and \
            self.pin.pin_type == TACK_Pin_Type.out_of_chain_key:
            if self.pin.pin_target_sha256 != SHA256(self.sig.out_of_chain_key):
                raise SyntaxError("TACK_Pin doesn't match TACK_Sig")
        
    def write(self):        
        b = bytearray(0)
        if self.pin: 
            # type=SEQ,len=82(for whole ext),type=6,len=9(for OID),
            # OID,type=4,len=69,TACK_Pin 
            b += bytearray([0x30,0x52,6,9]) + self.oid_pin + \
                         bytearray([4,0x45]) + self.pin.write()
        if self.sig:
            # type=SEQ,len=173(for whole ext),type=6,len=9(for OID),
            # type=4,len=169,TACK_Sig
            b += bytearray([0x30,0x81,0xB7,6,9]) + self.oid_sig + \
                         bytearray([4,0x81,0xA9]) + self.sig.write()
        if self.codes:
            # type=SEQ,len=?,type=6,len=9(for OID),
            # type=4,len=?,TACK_Pin_Break_Codes
            codesBytes = self.codes.write()
            b2 = bytearray([4]) + asn1Length(len(codesBytes)) + codesBytes
            b2 = bytearray([6,9]) + self.oid_codes + b2
            b2 = bytearray([0x30]) + asn1Length(b2) + b2
        
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
        strList = []
        if self.pin:
            strList.append(self.pin.writeText())
        if self.sig:
            strList.append(self.sig.writeText())
        if self.codes:
            strList.append(self.codes.writeText())
        return "TACK_Cert:\n\n" + "\n\n".join(strList)+"\n"


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

class TACK_SecretFileViewer:
    def __init__(self):
        self.version = 0
        self.iter_count = 0
        self.salt = bytearray(16)
        self.IV = bytearray(16)
        self.ciphertext = bytearray(64)
        self.out_of_chain_key = bytearray(64)
        self.pin_break_code_sha256 = bytearray(32)
        self.mac = bytearray(32)
        
    def parse(self, b):
        p = Parser(b)
        magic = p.getBytes(3)
        if magic != TACK_SecretFile.magic:
            raise SyntaxError("Bad magic number in Secret File")
        self.version = p.getInt(1)
        if self.version != 1:
            raise SyntaxError("Bad version in Secret File")
        self.iter_count = p.getInt(4)
        self.salt = p.getBytes(16)
        self.IV = p.getBytes(16)
        self.ciphertext = p.getBytes(64)
        self.out_of_chain_key = p.getBytes(64)
        self.pin_break_code_sha256 = p.getBytes(32)
        self.mac = bytearray(p.getBytes(32))
        assert(p.index == len(b)) # did we fully consume byte-array?

    def writeText(self):
        s = \
"""version                = %d
iter_count             = %d
salt                   = 0x%s
IV                     = 0x%s
ciphertext             = 0x%s
out_of_chain_key       = 0x%s
pin_break_code_sha256  = 0x%s
mac                    = 0x%s""" % \
        (self.version, 
        self.iter_count,
        writeBytes(self.salt),
        writeBytes(self.IV),
        writeBytes(self.ciphertext),
        writeBytes(self.out_of_chain_key),
        writeBytes(self.pin_break_code_sha256),
        writeBytes(self.mac))
        return "TACK_SecretFile (encrypted):\n"+s        
        
    
class TACK_SecretFile:
    magic = bytearray([0x9A,0x61,0x27])

    def __init__(self):
        self.version = 0
        self.private_key = bytearray(32)
        self.out_of_chain_key = bytearray(64)
        self.pin_break_code = bytearray(24)
        self.out_of_chain_key = bytearray(64)
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

    def sign(self, bytesToHash):
        private_key = bytesToNumber(self.private_key)
        g = ecdsa.generator_256
        n = g.order()
        x = bytesToNumber(self.out_of_chain_key[:32])
        y = bytesToNumber(self.out_of_chain_key[32:])        
        pubkey = ecdsa.Public_key(g, ellipticcurve.Point(g.curve(), x,y))
        privkey = ecdsa.Private_key(pubkey, private_key)
        hash = SHA256(bytesToHash)
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
        magic = p.getBytes(3)
        if magic != TACK_SecretFile.magic:
            raise SyntaxError("Bad magic number in Secret File")
        self.version = p.getInt(1)
        if self.version != 1:
            raise SyntaxError("Bad version in Secret File")
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
        w = Writer(232)
        w.add(TACK_SecretFile.magic, 3)
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
    #print "\nTACK_Pin:\n", pin2.writeText()

    # Test reading/writing TACK_Sig
    sig.sig_type = TACK_Sig_Type.in_chain_cert
    sig.sig_expiration = 1000000000
    sig.sig_revocation = 1000000000
    sig.sig_target_sha256 = bytearray(range(0, 32))
    sig.out_of_chain_key = bytearray(range(32, 96))
    sig.signature = bytearray(range(96, 160))
    sig2 = TACK_Sig()
    sig2.parse(sig.write())
    assert(sig.write() == sig2.write())
    #print "\nTACK_Sig:\n", sig2.writeText()

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
    #print "\nTACK_Pin_Break_Codes:\n", codes2.writeText()
    

def testSecretFile():
    f = TACK_SecretFile()
    f.generate()
    
    b = f.write("abracadabra")
    f2 = TACK_SecretFile()
    assert(f2.parse(b, "abracadabra"))
    assert(f2.__dict__ == f.__dict__)

    f2.generate(bytearray("blablabla"))    
    h = bytearray(range(100,200))
    sig = f2.sign(h)

def testCert():
    sigDays = pinDays = 550 # About 1.5 years
    currentTime = int(time.time()/60) # Get time in minutes
    pinExp = currentTime + (24*60) * pinDays
    sigExp = currentTime + (24*60) * sigDays    
    
    sslBytes = bytearray(range(1,200))
    sf = TACK_SecretFile()
    sf.generate()    
        
    pin = TACK_Pin()
    pin.generate(TACK_Pin_Type.out_of_chain_key, 
                 pinExp,
                 SHA256(sf.out_of_chain_key),
                 sf.pin_break_code_sha256)
        
    sig = TACK_Sig()
    sig.generate(TACK_Sig_Type.in_chain_cert,
                 sigExp, 0, SHA256(sslBytes),
                 sf.out_of_chain_key, lambda b:sf.sign(b))
                     
    tc = TACK_Cert()
    tc.generate(pin, sig)

    tc2 = TACK_Cert()
    tc2.parse(tc.write())
    assert(tc.write() == tc2.write())

################ MAIN ###

import sys, getpass, getopt

def printUsage(s=None):
    if s:
        print "ERROR: %s" % s
    print
    print"Commands:"
    print "  new    <ssl_cert>"
    print "  update <ssl_cert>"
    print "  view   <file or site>"
    print
    sys.exit(-1)

def printError(s):
    print "ERROR: %s" % s
    sys.exit(-1)

def newSecretFile(extraRandStr=""):
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

def pin(argv, update=False):
    # First, argument parsing
    if len(argv) < 1:
        printUsage("Missing argument: SSL certificate file")    
    noArgArgs = ["--no_pem"]
    oneArgArgs= ["--sig_type", 
                "--pin_expiration", "--sig_expiration", 
                "--sig_revocation"]
    if not update:
        noArgArgs += ["--no_pin_break"]
        oneArgArgs += ["--pin_type"]

    sslName = argv[0]
    argsDict = {}    
    for arg in argv[1:]:
        parts = arg.split("=")
        if parts[0] in argsDict:
            printUsage("Duplicate argument: %s" % parts[0])
        if len(parts)==2:
            if not parts[0] in oneArgArgs:
                printUsage("Unknown or malformed argument: %s" % parts[0])
            argsDict[parts[0]] = parts[1]
        elif len(parts)==1:
            if not parts[0] in noArgArgs:
                printUsage("Unknown or malformed argument: %s" % parts[0])            
            argsDict[parts[0]] = None
        else:
            printUsage("Unknown or malformed argument: %s" % parts[0])

    # -1 args are for distinguishing between set/unset on cmdline, see below
    noPem = False
    noPinBreak = False
    pin_type = TACK_Pin_Type.out_of_chain_key
    sig_type = -1       # [default=in_chain_cert, see below]
    pin_expiration = -1
    sig_expiration = -1
    sig_revocation = -1

    if "--no_pem" in argsDict:
        noPem = True   
    if not update and "--no_pin_break" in argsDict:
        noPinBreak = True   
    if not update and "--pin_type" in argsDict:    
        val = argsDict["--pin_type"]
        if val == "in_chain_key":
            pin_type = TACK_Pin_Type.in_chain_key
        elif val == "in_chain_cert":
            pin_type = TACK_Pin_Type.in_chain_cert
        elif val == "out_of_chain_key":
            pin_type = TACK_Pin_Type.out_of_chain_key
        else:
            printUsage("Unrecognized pin_type")
    if "--sig_type" in argsDict:    
        val = argsDict["--sig_type"]
        if val == "in_chain_key":
            sig_type = TACK_Sig_Type.in_chain_key
        elif val == "in_chain_cert":
            sig_type = TACK_Sig_Type.in_chain_cert
        else:
            printUsage("Unrecognized sig_type")
    if "--pin_expiration" in argsDict:
        pin_expiration = parseTimeArg(argsDict["--pin_expiration"])
    if "--sig_expiration" in argsDict:
        sig_expiration = parseTimeArg(argsDict["--sig_expiration"])
    if "--sig_revocation" in argsDict:
        sig_revocation = parseTimeArg(argsDict["--sig_revocation"])

    defaultExpiration = getDefaultExpiration()
    if pin_expiration == -1:
        pin_expiration = defaultExpiration
    
    # Check the sig-relevant args, depending on whether there is a sig
    if pin_type == TACK_Pin_Type.out_of_chain_key:
        if sig_type == -1:
            sig_type = TACK_Sig_Type.in_chain_cert
        if sig_expiration == -1:
            sig_expiration = pin_expiration
        if sig_revocation == -1:
            sig_revocation = 0        
    if pin_type != TACK_Pin_Type.out_of_chain_key:
        if sig_type != -1:
            printError("--sig_type can only be used with out_of_chain_key pin")
        if sig_expiration != -1:
            printError("--sig_expiration can only be used with out_of_chain_key pin")
        if sig_revocation != -1:
            printError("--sig_revocation can only be used with out_of_chain_key pin")            
    
    # Open the files
    try:
        sslBytes = bytearray(open(sslName).read())
    except IOError:
        printUsage("SSL certificate file not found: %s" % argv[0])

    try:
        tcBytes = bytearray(open("__TACK_certificate.dat", "rb").read())
    except IOError:
        if update:
            printUsage("__TACK_certificate.dat not found")
        tcBytes = None

    try:    
        sfBytes = bytearray(open("__TACK_secret_file.dat", "rb").read())
    except IOError:
        if update:
            printUsage("__TACK_secret_file.dat not found")
        sfBytes = None

    # Parse file contents
    sslc = SSL_Cert()
    try:
        sslc.parse(sslBytes)        
    except SyntaxError:
        printUsage("SSL certificate file malformed: %s" % argv[0])

    tc = TACK_Cert()
    if tcBytes:
        print "__TACK_certificate.dat found, updating..."
        try:
            tc.parse(tcBytes)
        except SyntaxError:
            printUsage("__TACK_certificate.dat malformed")
    else:
        tc.generate()
        print "No __TACK_certificate.dat found, creating new one..."

    if sfBytes:
        print "__TACK_secret_file.dat found, opening..."        
        try:
            sf = openSecretFile(sfBytes)        
        except SyntaxError:
            printUsage("__TACK_secret_file.dat malformed")        
    else:
        print "No __TACK_secret_file.dat, creating new one..."
        sf = newSecretFile()

    # Check existing TACK_Pin and TACK_Sig
    if update:
        if not tc.pin:
            printError("__TACK_certificate.dat has no pin")
        if tc.pin.isExpired():
            printError("The pin is expired")
        tc.sig = None
    elif not update and tc.pin:
        if tc.pin.isExpired():
            print "The existing pin is expired"
            query = raw_input('There is an existing (expired) pin, choose "y" to replace: ')
        query = raw_input('There is an existing pin, choose "y" to replace: ')
        if query != "y":
            printError("Cancelled")
        tc.pin = None
        tc.sig = None

    # Produce the TACK_Pin (if "new")
    if not update:
        if pin_type == TACK_Pin_Type.out_of_chain_key:
            pin_target_sha256 = SHA256(sf.out_of_chain_key)
        elif pin_type == TACK_Pin_Type.in_chain_key:
            pin_target_sha256 = sslc.in_chain_key_sha256
        elif pin_type == TACK_Pin_Type.in_chain_cert:
            pin_target_sha256 = sslc.in_chain_cert_sha256
        if noPinBreak:
            # A malicious os.urandom can't control the code:
            pin_break_code_sha256 = SHA256(os.urandom(64))
        else:
            pin_break_code_sha256 = sf.pin_break_code_sha256
        tc.pin = TACK_Pin()            
        tc.pin.generate(pin_type, pin_expiration, 
                     pin_target_sha256,
                     pin_break_code_sha256)

    # Produce the TACK_Sig (if "new" or "update" and out_of_chain_key)
    if pin_type == TACK_Pin_Type.out_of_chain_key:
        if sig_type == TACK_Sig_Type.in_chain_key:
            sig_target_sha256 = sslc.in_chain_key_sha256
        elif sig_type == TACK_Sig_Type.in_chain_cert:
            sig_target_sha256 = sslc.in_chain_cert_sha256
        tc.sig = TACK_Sig()
        tc.sig.generate(sig_type, sig_expiration, sig_revocation, 
                        sig_target_sha256, sf.out_of_chain_key, 
                        lambda b:sf.sign(b))
    
    b = tc.write()
    if not noPem:
        b = pemCert(b)
    f = open("__TACK_certificate.dat", "wb")
    f.write(b)
    f.close()
    return tc
 
def view(argv):
    if len(argv) != 1:
        printUsage("Missing argument: object to view")
    b = bytearray(open(argv[0]).read())
    # If it's a secret file
    if len(b) == 232 and b[:3] == TACK_SecretFile.magic:
        sfv = TACK_SecretFileViewer()
        sfv.parse(b)
        print "\n"+sfv.writeText()
    # If not it could be a certificate
    else: 
        try:
            written=0            
            tc = TACK_Cert()
            tc.parse(b)
            if tc.pin or tc.sig or tc.codes:
                print "\n"+tc.writeText()
                written = 1      
        except SyntaxError:
            pass
        if not written:
            try:
                sslc = SSL_Cert()
                sslc.parse(b)
                print "\n"+sslc.writeText()      
            except SyntaxError:
                printUsage("Unrecognized file type")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        printUsage("Missing command")
    elif sys.argv[1] == "test":
        testCert()
        testStructures()
        testSecretFile()        
    elif sys.argv[1] == "new":
        pin(sys.argv[2:], False)
    elif sys.argv[1] == "update":
        pin(sys.argv[2:], True)
    elif sys.argv[1] == "view":
        view(sys.argv[2:])
    else:
        printUsage("Unknown command: %s" % sys.argv[1])



    

#! /usr/bin/env python

################ COMPAT ###

import array

# Add python 3.0 version?
def createByteArrayZeros(howMany):
    return array.array('B', [0] * howMany)
    
def createByteArraySequence(seq):
    return array.array('B', seq)    
    
def bytesToString(bytes):
    return bytes.tostring()

def stringToBytes(s):
    bytes = createByteArrayZeros(0)
    bytes.fromstring(s)
    return bytes    


################ CRYPTOMATH ###

import math

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
    bytes = createByteArrayZeros(howManyBytes)
    for count in range(howManyBytes-1, -1, -1):
        bytes[count] = int(n % 256)
        n >>= 8
    return bytes
    
def stringToNumber(s):
    bytes = stringToBytes(s)
    return bytesToNumber(bytes)
    

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


################ CODEC ###

class Writer:
    def __init__(self, totalLength):
        self.index = 0
        self.bytes = createByteArrayZeros(totalLength)

    def add(self, x, elementLength):
        """Writes 'elementLength' bytes, input is either an integer (written as big-endian) or a sequence of bytes"""
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
        """Writes a sequence of elements prefixed by a total-length field of lengthLength bytes"""
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
        return [self.getBytes(elementLength) for x in range(dataLength/elementLength)]


################ CONSTANTS ###

class TACK_Pin_Type:
    in_chain = 1
    out_of_chain = 2
    
class TACK_Break_Type:
    none = 0
    sha256 = 1

class TACK_Signature_Type:
    ecdsa_p256_sha256 = 1
    

################ STRUCTURES ###
        
class TACK_Pin:
    def __init__(self):
        self.pin_type = 0
        self.pin_expiration = 0
        self.spki_sha256 = createByteArrayZeros(32)
        self.out_of_chain_key_sha256 = createByteArrayZeros(32)
        self.break_type = 0
        self.commitment_sha256 = createByteArrayZeros(32)        
    
    def parse(self, b):
        p = Parser(b)
        self.pin_type = p.getInt(1)
        if self.pin_type not in (TACK_Pin_Type.in_chain, TACK_Pin_Type.out_of_chain):
            raise SyntaxError()
        self.pin_expiration = p.getInt(4)
        if self.pin_type == TACK_Pin_Type.in_chain:
            self.spki_sha256 = p.getBytes(32)
        elif self.pin_type == TACK_Pin_Type.out_of_chain:
            self.out_of_chain_key_sha256 = p.getBytes(32)            
        self.break_type = p.getInt(1)
        if self.break_type not in (TACK_Break_Type.none, TACK_Break_Type.sha256):
            raise SyntaxError()
        if self.break_type == TACK_Break_Type.sha256:
            self.commitment_sha256 = p.getBytes(32)
        assert(p.index == len(b)) # did we fully consume byte-array?
        
    def write(self):        
        if self.pin_type not in (TACK_Pin_Type.in_chain, TACK_Pin_Type.out_of_chain):
            raise SyntaxError()        
        if self.break_type not in (TACK_Break_Type.none, TACK_Break_Type.sha256):
            raise SyntaxError()
        if self.break_type == TACK_Break_Type.sha256:
            w = Writer(70)
        else:
            w = Writer(38)
        w.add(self.pin_type, 1)
        w.add(self.pin_expiration, 4)
        if self.pin_type == TACK_Pin_Type.in_chain:
            w.add(self.spki_sha256, 32)
        elif self.pin_type == TACK_Pin_Type.out_of_chain:
            w.add(self.out_of_chain_key_sha256, 32)  
        w.add(self.break_type, 1)
        if self.break_type == TACK_Break_Type.sha256:
            w.add(self.commitment_sha256, 32)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?            
        return w.bytes  
     
        
class TACK_Signature:    
    def __init__(self):
        self.signature_type = 0
        self.out_of_chain_key = createByteArrayZeros(64)
        self.spki_sha256 = createByteArrayZeros(32)
        self.sig_expiration = 0
        self.sig_generation = 0        
        self.signature = createByteArrayZeros(64)
    
    def parse(self, b):
        p = Parser(b)
        self.signature_type = p.getInt(1)
        if self.signature_type not in (TACK_Signature_Type.ecdsa_p256_sha256, ):
            raise SyntaxError()
        self.out_of_chain_key = p.getBytes(64)
        self.spki_sha256 = p.getBytes(32)
        self.sig_expiration = p.getInt(4)
        self.sig_generation = p.getInt(4)
        self.signature = p.getBytes(64)
        assert(p.index == len(b)) # did we fully consume byte-array?
        
    def write(self):
        if self.signature_type not in (TACK_Signature_Type.ecdsa_p256_sha256, ):
            raise SyntaxError()        
        w = Writer(169)
        w.add(self.signature_type, 1)
        w.add(self.out_of_chain_key, 64)
        w.add(self.spki_sha256, 32)
        w.add(self.sig_expiration, 4)
        w.add(self.sig_generation, 4)
        w.add(self.signature, 64)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?
        return w.bytes
        
        
class TACK_Pin_Break_Codes:
    def __init__(self):
        self.pin_break_codes = []
        
    def parse(self, b):
        p = Parser(b)
        self.pin_break_codes = p.getVarSeqBytes(16, 2)
        if len(self.pin_break_codes) < 0:
            raise SyntaxError()
        if len(self.pin_break_codes) > 256:
            raise SyntaxError()    
        assert(p.index == len(b)) # did we fully consume byte-array?
        
    def write(self):
        w = Writer(2 + 16*len(self.pin_break_codes))
        w.addVarSeq(self.pin_break_codes, 16, 2)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?        
        return w.bytes




################ SECRET FILE ###

import os, hmac, hashlib, rijndael, ecdsa

def xorstr(s1, s2):
    return "".join(map(lambda x, y: chr(ord(x) ^ ord(y)), s1, s2))

def xorbytes(s1, s2):
    return "".join(map(lambda x, y: x ^ y), s1, s2)


# Uses PBKDF2-HMAC-SHA256 to produce a 32-byte key
def pbkdf2_hmac_sha256(password, salt, iterations):
    m = salt + "\x00\x00\x00\x01"
    result = bytesToString(createByteArrayZeros(32))
    for c in range(iterations):
        m = hmac.new(password, m, hashlib.sha256).digest()
        result = xorstr(m, result)
    return result

# Uses PBKDF2, then HMAC-SHA256 as PRF to derive independent 32-byte keys
def deriveSecretFileKeys(password, salt):
    masterKey = pbkdf2_hmac_sha256(password, salt, 8192)
    encKey = hmac.new(masterKey, "\x01", hashlib.sha256).digest()
    authKey = hmac.new(masterKey, "\x02", hashlib.sha256).digest()
    return (encKey, authKey)

def aes_cbc_decrypt(key, IV, ciphertext):
    cipher = rijndael.rijndael(key, 16)
    assert(len(ciphertext) % 16 == 0) # no padding
    chainBlock = IV
    plaintext = "" # not efficient, but doesn't matter here
    for c in range(len(ciphertext)/16):
        cipherBlock = ciphertext[c*16 : (c*16)+16]
        plaintext += xorstr(cipher.decrypt(cipherBlock), chainBlock)
        chainBlock = cipherBlock
    return plaintext

def aes_cbc_encrypt(key, IV, plaintext):
    cipher = rijndael.rijndael(key, 16)
    assert(len(plaintext) % 16 == 0) # no padding
    chainBlock = IV
    ciphertext = "" # not efficient, but doesn't matter here
    for c in range(len(plaintext)/16):
        plainBlock = plaintext[c*16 : (c*16)+16]
        chainBlock = cipher.encrypt(xorstr(plainBlock, chainBlock))
        ciphertext += chainBlock
    return ciphertext     
    
class TACK_SecretFile:
    def __init__(self):
        self.version = 0
        self.private_key = createByteArrayZeros(32)
        self.pin_break_code = createByteArrayZeros(16)
        
    def generate(self, extraRandBytes=None):
        self.version = 1        
        # ECDSA key generation per FIPS 186-3 B.4.1
        # (except we use 32 extra random bytes instead of 8 before reduction)
        # Random bytes taken from /dev/urandom as well as any extraRandBytes
        # REVIEW THIS CAREFULLY!!!  CHANGE AT YOUR PERIL!!!
        n = ecdsa.generator_256.order()
        randStr0_1 = os.urandom(64)
        if extraRandBytes:
            randStr0_2 = bytesToString(extraRandBytes)
        else:
            randStr0_2 = ""
        randStr0 = randStr0_1 + randStr0_2
        randStr1 = hmac.new(randStr0, "\x01", hashlib.sha256).digest()
        randStr2 = hmac.new(randStr0, "\x02", hashlib.sha256).digest()
        randStr3 = hmac.new(randStr0, "\x03", hashlib.sha256).digest()
        randStr = randStr1 + randStr2    
        c = stringToNumber(randStr) 
        d = (c % (n-1))+1        
        self.private_key = numberToBytes(d, 32)
        self.pin_break_code = stringToBytes(randStr3[:16])

    def sign(self, hash):
        private_key = bytesToNumber(self.private_key)
        g = ecdsa.generator_256
        n = g.order()
        pubkey = ecdsa.Public_key(g, g * private_key)
        privkey = ecdsa.Private_key(pubkey, private_key)
        # Generating random nonce k per FIPS 186-3 B.5.1:
        # (except we use 32 extra bytes instead of 8 before reduction)
        # Random bytes taken from /dev/urandom as well as HMAC(privkey,hash)
        # REVIEW THIS CAREFULLY!!!  CHANGE AT YOUR PERIL!!!
        randStr0_1 = os.urandom(64)
        randStr0_2 = hmac.new(bytesToString(self.private_key), 
                            bytesToString(hash), hashlib.sha256).digest()
        randStr0 = randStr0_1 + randStr0_2                    
        randStr1 = hmac.new(randStr0, "\x01", hashlib.sha256).digest()
        randStr2 = hmac.new(randStr0, "\x02", hashlib.sha256).digest()                        
        randStr = randStr1 + randStr2    
        c = stringToNumber(randStr) 
        k = (c % (n-1))+1                
        hashNum = bytesToNumber(hash)
        sig = privkey.sign(hashNum, k)
        # Double-check before returning
        assert(pubkey.verifies(hashNum, sig))        
        return numberToBytes(sig.r) + numberToBytes(sig.s)

    def verify(self, hashVal):
        private_key = bytesToNumber(self.private_key)
        g = ecdsa.generator_256
        n = g.order()
        pubkey = ecdsa.Public_key(g, g * private_key)
        ##!!!

    def parse(self, b, password):
        p = Parser(b)
        self.version = p.getInt(1)
        if self.version != 1:
            raise SyntaxError()
        salt = bytesToString(p.getBytes(16))
        IV = bytesToString(p.getBytes(16))
        ciphertext = bytesToString(p.getBytes(48))
        mac = bytesToString(p.getBytes(32))
        assert(p.index == len(b)) # did we fully consume byte-array?

        encKey, authKey = deriveSecretFileKeys(password, salt)
        calcMac = hmac.new(authKey, IV+ciphertext, hashlib.sha256).digest()
        if calcMac != mac:
            return False        
        plaintext = aes_cbc_decrypt(encKey, IV, ciphertext)
        self.private_key = stringToBytes(plaintext[:32])
        self.pin_break_code = stringToBytes(plaintext[32:])
        return True
    
    def write(self, password):
        salt = os.urandom(16)
        IV = os.urandom(16)
        encKey, authKey = deriveSecretFileKeys(password, salt)
        plaintext = bytesToString(self.private_key) + bytesToString(self.pin_break_code)
        ciphertext = aes_cbc_encrypt(encKey, IV, plaintext)
        mac = hmac.new(authKey, IV+ciphertext, hashlib.sha256).digest()        
        w = Writer(113)
        w.add(self.version, 1)
        w.add(stringToBytes(salt), 16)
        w.add(stringToBytes(IV), 16)
        w.add(stringToBytes(ciphertext), 48)
        w.add(stringToBytes(mac), 32)
        assert(w.index == len(w.bytes)) # did we fill entire byte-array?
        return w.bytes


################ TESTS ###


def testStructures():
    pin = TACK_Pin()
    sig = TACK_Signature()
    codes = TACK_Pin_Break_Codes()
    
    pin.pin_expiration = 12345;
    pin.out_of_chain_key_sha256 = createByteArraySequence(range(32))
    pin.commitment_sha256 = createByteArraySequence(range(32,64))    
    pin.spki_sha256 = createByteArraySequence(range(64,96))    

    # Test reading/writing OOC pin with pin-break
    pin.pin_type = TACK_Pin_Type.out_of_chain
    pin.break_type = TACK_Break_Type.sha256
    pin2 = TACK_Pin()
    pin2.parse(pin.write())
    assert(pin.write() == pin2.write())

    # Test reading/writing OOC pin with no pin-break    
    pin.pin_type = TACK_Pin_Type.out_of_chain
    pin.break_type = TACK_Break_Type.none    
    pin2.parse(pin.write())
    assert(pin.write() == pin2.write())

    # Test reading/writing in-chain pin with pin-break        
    pin.pin_type = TACK_Pin_Type.in_chain
    pin.break_type = TACK_Break_Type.sha256    
    pin2.parse(pin.write())
    assert(pin.write() == pin2.write())

    # Test reading/writing in-chain pin with no pin-break    
    pin.pin_type = TACK_Pin_Type.in_chain
    pin.break_type = TACK_Break_Type.none    
    pin2.parse(pin.write())
    assert(pin.write() == pin2.write())
    
    # Test reading/writing TACK_Signature
    sig.signature_type = TACK_Signature_Type.ecdsa_p256_sha256
    sig.out_of_chain_key = createByteArraySequence(range(0, 64))
    sig.spki_sha256 = createByteArraySequence(range(64, 96))
    sig.sig_expiration = 121
    sig.sig_generation = 3
    sig.signature = createByteArraySequence(range(96, 160))
    sig2 = TACK_Signature()
    sig2.parse(sig.write())
    assert(sig.write() == sig2.write())

    # Test reading/writing TACK_Pin_Break_Codes with 1 code
    codes.pin_break_codes = [createByteArraySequence(range(0,16))]
    codes2 = TACK_Pin_Break_Codes()
    codes2.parse(codes.write())
    assert(codes.write() == codes2.write())

    # Test reading/writing TACK_Pin_Break_Codes with 3 code
    codes.pin_break_codes = [createByteArraySequence(range(0,16)),
                            createByteArraySequence(range(30, 46)),
                            createByteArraySequence(range(60, 76))]
    codes2 = TACK_Pin_Break_Codes()
    codes2.parse(codes.write())
    assert(codes.write() == codes2.write())

def testSecretFile():
    f = TACK_SecretFile()
    f.version = 1
    f.private_key = createByteArraySequence(range(0, 32))
    f.pin_break_code = createByteArraySequence(range(100, 116))
    
    b = f.write("abracadabra")
    f2 = TACK_SecretFile()
    f2.parse(b, "abracadabra")
    assert(f2.__dict__ == f.__dict__)

    f2.generate(stringToBytes("blablabla"))    
    h = createByteArraySequence(range(200, 232))
    sig = f2.sign(h)



################ MAIN ###

import sys, getpass, getopt

def printUsage():
    print""
    print " create_all"
    print " update_all"
    print ""
    print " create_secret [-r <extra_random> -p <password> -o <output_file>]"
    print ""
    print " create_pin [-s <secret_file> -c <cert_file> -o <output_file>"
    print "  --in_chain --no_pin_break --hash_key --no_prompt" 
    print "  --pin_expiration <datetime>]"
    print ""
    print " create_sig [-s <secret_file> -p <password> -c <cert_file> -o <output_file>"
    print "  --hash_key --inc_generation --no_prompt --sig_expiration <datetime>]"
    print ""
    print " update_pin [-t <TACK_cert_file> -o <output_file>"
    print "  --pin_break_secret_file <secret_file> --pin_break_password <password>"   
    print "  --no_prompt --pin_expiration <datetime>" 
    print ""
    sys.exit(-1)

def createSecret(argv):    
    passwordStr = ""
    extraRandStr = ""
    fname = ""
    
    # Parse cmdline opts
    opts, argv = getopt.getopt(argv, "r:p:o:")
    for o, a in opts:
        if o == "-r":
            if extraRandStr:
                print"ERROR: duplicate options"
                printUsage()
            extraRandStr = a
        if o == "-p":
            if passwordStr:
                print"ERROR: duplicate options"
                printUsage()                
            passwordStr = a
        if o == "-o":
            if fname:
                print"ERROR: duplicate options"
                printUsage()            
            fname = a            
    if argv:
        print "ERROR: unknown options"
        printUsage()

    # Prompt for opts
    if not extraRandStr:
        while len(extraRandStr)<20:
            extraRandStr = getpass.getpass ("Enter at least 20 random keystrokes: ")
    while not passwordStr:
        password1, password2 = "a", "b"
        while password1 != password2:
            password1 = getpass.getpass("Enter password for secret file: ")    
            password2 = getpass.getpass("Re-enter password for secret file: ")  
            if password1 != password2:
                print "PASSWORDS DON'T MATCH!\n"      
            else:
                passwordStr = password1
    if not fname:
        fname = raw_input("Enter filename for secret file [TACK_SECRET_FILE.dat]: ")
        if not fname:
            fname = "TACK_SECRET_FILE.dat"
        
    sf = TACK_SecretFile()
    sf.generate(stringToBytes(extraRandStr))
    b = sf.write(passwordStr)
    f = open(fname, "wb")
    f.write(bytesToString(b))
    f.close()
    

if __name__ == '__main__':
    if len(sys.argv) < 2:
        printUsage()
    if sys.argv[1] == "create_secret":
        createSecret(sys.argv[2:])
    elif sys.argv[1] == "create_pin":
        createPin(sys.argv[2:])
    elif sys.argv[1] == "create_sig":
        createSig(sys.argv)
    elif sys.argv[1] == "update_pin":
        updatePin(sys.argv)
    elif sys.argv[1] == "test":
        testStructures()
        testSecretFile()        
    else:
        printUsage()



    

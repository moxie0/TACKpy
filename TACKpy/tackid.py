# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

""" 
A custom base32 alphabet is used consisting of the uppercase letters
followed by numbers, with the visually ambiguous pairs (2Z) and (0O) removed:

ABCDEFGHIJKLMNPQRSTUVWXY13456789

This alphabet was chosen to maximize visual distinctiveness between
characters. Unlike more common base32 alphabets [BASE32], this alphabet solely
uses uppercase characters, which seem more distinctive due to their larger
size. See Appendix A for more discussion.


"""
################ FINGERPRINTS ###

alphabet = "abcdefghijkLmnpqrstuvwxy13456789"

revAlphabet = {'a':0, 'b':1, 'c':2, 'd':3, 'e':4, 'f':5, 'g':6, 'h':7,
    'i':8, 'j':9, 'k':10, 'L':11, 'm':12, 'n':13, 'p':14, 'q':15, 
    'r':16, 's':17, 't':18, 'u':19, 'v':20, 'w':21, 'x':22, 'y':23, '1':24, 
    '3':25, '4':26, '5':27, '6':28, '7':29, '8':30, '9':31}

def base32EncodeIntList(listInts):
    s = ""
    for x in listInts:
        assert(x < 32)
        s += alphabet[x]
    return s

def base32DecodeToIntList(s):
    listInts = []
    for c in s:
        if c not in revAlphabet:
            raise SyntaxError("Invalid character in TACK ID")
        listInts.append(revAlphabet[c])
    return listInts

def hashToTACKID(b):
    assert(len(b) == 15)
    listInts = [1] # 5 bit header = V1
    nextInt = 0
    outMask = 0x10
    for x in b:
        for inMask in [0x80,0x40,0x20,0x10,0x8,0x4,0x2,0x1]:
            if x & inMask:
                nextInt |= outMask
            outMask >>= 1
            if outMask == 0:
                listInts.append(nextInt)
                nextInt = 0
                outMask = 0x10
    s = base32EncodeIntList(listInts)    
    s = "%s.%s.%s.%s.%s" % (s[:5],s[5:10],s[10:15],s[15:20],s[20:25])
    return s            

def TACKIDtoHash(s):
    if len(s) != 29:
        raise SyntaxError("TACK ID incorrect length")
    if s[5] != '.' or s[11] != '.' or s[17] != '.' or s[23] != '.':
        raise SyntaxError("TACK ID incorrectly formatted")
    s = s[0:5] + s[6:11] + s[12:17] + s[18:23] + s[24:29]
    listInts = base32DecodeToIntList(s)
    b = bytearray()
    nextByte = 0
    outMask = 0x10
    for x in listInts:
        for inMask in (0x10,0x8,0x4,0x2,0x1):
            if x & inMask:
                nextByte |= outMask
            outMask >>= 1
            if outMask == 0:
                b.append(nextByte)
                nextByte = 0
                outMask = 0x80
    if b[0] != 0x01:
        raise SyntaxError("TACK ID has wrong version") 
    return b[1:]
                
def testTACKID():
    import os
    print("Testing TACK ID")
    b = bytearray(15) # All zeros "hash value"
    assert(b == TACKIDtoHash(hashToTACKID(b)))     
    b = bytearray(range(100,115))
    assert(b == TACKIDtoHash(hashToTACKID(b)))
    for x in range(10):
        b = bytearray(os.urandom(15))
        assert(b == TACKIDtoHash(hashToTACKID(b)))
    return 1

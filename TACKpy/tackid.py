# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

""" 
TACK ID alphabet base32 encoding

"""

from .compat import b2a_base32

################ FINGERPRINTS ###

def hashToTACKID(b):
    assert(len(b) == 15)
    s = b2a_base32(b).lower()
    s = "b"+s
    return "%s.%s.%s.%s.%s" % (s[:5],s[5:10],s[10:15],s[15:20],s[20:25])
    s2 = "b"
    for c in s:
        if c.isdigit():
            s2 += chr(ord(c)+2)
        elif c == 'z':
            s2 += '3'
        elif c == 'l':
            s2 += 'L'
        elif c == 'o':
            s2 += '1'
        else:
            s2 += c
    return "%s.%s.%s.%s.%s" % (s2[:5],s2[5:10],s2[10:15],s2[15:20],s2[20:25])

# old version below...

alphabet = "abcdefghijkLmn1pqrstuvwxy3456789"

def base32EncodeIntList(listInts):
    s = ""
    for x in listInts:
        assert(x < 32)
        s += alphabet[x]
    return s

def hashToTACKIDold(b):
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

                
def testTACKID():
    import os
    print("Testing TACK ID")
    for x in range(1000):
        b = bytearray(os.urandom(15))
        tackID1 = hashToTACKID(b)
        tackID2 = hashToTACKIDold(b)
        assert(tackID1 == tackID2)
    return 1

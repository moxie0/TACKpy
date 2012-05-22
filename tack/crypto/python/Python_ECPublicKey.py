# Authors: 
#   Trevor Perrin
#
# See the LICENSE file for legal information regarding use of this file.

from tack.compat import b2a_base32
from tack.crypto.Digest import Digest
from tack.crypto.python.ecdsa import Public_key, Point, generator_256, Signature
from tack.crypto.python.cryptomath import bytesToNumber

class Python_ECPublicKey:

    def __init__(self, rawPublicKey):
        assert(rawPublicKey is not None)
        assert(len(rawPublicKey) == 64)

        self.rawPublicKey = rawPublicKey

    def verify(self, data, signature):
        assert(len(signature) == 64)
        hashNum = bytesToNumber(Digest.SHA256(data))
        g = generator_256  
        x = bytesToNumber(self.rawPublicKey[ : 32])
        y = bytesToNumber(self.rawPublicKey[32 : ])        
        pubkey = Public_key(g, Point(g.curve(), x,y))
        sig = Signature(bytesToNumber(signature[:32]), 
                        bytesToNumber(signature[32:]))
        return pubkey.verifies(hashNum, sig)        

    def getRawKey(self):
        return self.rawPublicKey

    def getFingerprint(self):
        digest = Digest.SHA256(self.rawPublicKey)
        assert(len(digest) == 32)
        s = b2a_base32(digest).lower()[:25]
        return "%s.%s.%s.%s.%s" % (s[:5],s[5:10],s[10:15],s[15:20],s[20:25])

    def __str__(self):
        return self.getFingerprint()
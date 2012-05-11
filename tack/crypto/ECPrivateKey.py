from M2Crypto import EC, BIO
import math
from tack.compat import a2b_hex
from tack.crypto.ASN1 import toAsn1IntBytes, asn1Length, ASN1Parser
from tack.crypto.Digest import Digest
from tack.crypto.ECPublicKey import ECPublicKey
from tack.util.PEMEncoder import PEMEncoder

class ECPrivateKey:

    def __init__(self, rawPrivateKey, rawPublicKey, ec=None):
        assert(rawPrivateKey is not None and rawPublicKey is not None)
        self.ec            = ec
        self.rawPrivateKey = rawPrivateKey
        self.rawPublicKey  = rawPublicKey

        if not self.ec:
            self.ec = self._constructEcFromRawKeys(rawPrivateKey, rawPublicKey)

    def sign(self, data):
        # Produce ASN.1 signature
        hash         = Digest.SHA256(data)
        asn1SigBytes = self.ec.sign_dsa_asn1(hash)

        # Convert stupid ASN.1 signature into 64-byte signature
        # Double-check before returning
        sigBytes = self._convertToRawSignature(asn1SigBytes)

        assert(ECPublicKey(self.rawPublicKey, self.ec).verify(data, sigBytes))
        return sigBytes

    def getRawKey(self):
        return self.rawPrivateKey

    def _constructEcFromRawKeys(self, rawPrivateKey, rawPublicKey):
        assert(len(rawPrivateKey) == 32)
        assert(len(rawPublicKey) == 64)
        bytes1 = a2b_hex("02010104")
        bytes2 = a2b_hex("a00a06082a8648ce3d030107a14403420004")
        rawPrivateKey = toAsn1IntBytes(rawPrivateKey)
        b = bytes1 + asn1Length(len(rawPrivateKey)) + rawPrivateKey +\
            bytes2 + rawPublicKey
        b = bytearray([0x30]) + asn1Length(len(b)) + b
        pemPrivKeyBytes = PEMEncoder(b).getEncoded("EC PRIVATE KEY")

        return EC.load_key_bio(BIO.MemoryBuffer(pemPrivKeyBytes))


    def _convertToRawSignature(self, signature):
        parser = ASN1Parser(bytearray(signature))
        r = self._bytesToNumber(parser.getChild(0).value)
        s = self._bytesToNumber(parser.getChild(1).value)
        return self._numberToBytes(r, 32) + self._numberToBytes(s, 32)


    def _bytesToNumber(self, bytes):
        "Convert a sequence of bytes (eg bytearray) into integer."
        total = 0
        multiplier = 1
        for count in range(len(bytes)-1, -1, -1):
            byte = bytes[count]
            total += multiplier * byte
            multiplier *= 256
        return total

    def _numberToBytes(self, n, howManyBytes=None):
        """Convert an integer into a bytearray, zero-pad to howManyBytes.

        The returned bytearray may be smaller than howManyBytes, but will
        not be larger.  The returned bytearray will contain a big-endian
        encoding of the input integer (n).
        """
        if not howManyBytes:
            howManyBytes = self._numBytes(n)
        bytes = bytearray(howManyBytes)
        for count in range(howManyBytes-1, -1, -1):
            bytes[count] = int(n % 256)
            n >>= 8
        return bytes

    def _numBytes(self, n):
        "Return the number of bytes needed to represent the integer n."
        if not n:
            return 0
        bits = self._numBits(n)
        return int(math.ceil(bits / 8.0))

    def _numBits(self, n):
        "Return the number of bits needed to represent the integer n."
        if not n:
            return 0
        s = "%x" % n
        return ((len(s)-1)*4) +\
               {'0':0, '1':1, '2':2, '3':2,
                '4':3, '5':3, '6':3, '7':3,
                '8':4, '9':4, 'a':4, 'b':4,
                'c':4, 'd':4, 'e':4, 'f':4,
                }[s[0]]

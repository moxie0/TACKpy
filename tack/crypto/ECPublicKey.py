from M2Crypto import EC, BIO
from tack.compat import a2b_hex
from tack.compat import b2a_base32
from tack.crypto.ASN1 import toAsn1IntBytes, asn1Length
from tack.crypto.Digest import Digest
from tack.util.PEMEncoder import PEMEncoder

class ECPublicKey:

    def __init__(self, rawPublicKey, ec=None):
        assert(rawPublicKey is not None)
        self.ec           = ec
        self.rawPublicKey = rawPublicKey

        if not self.ec:
            self.ec = self._constructEcFromRawKey(self.rawPublicKey)

    def verify(self, data, signature):
        # Convert 64-byte signature into a stupid ASN.1 signature
        asn1SigBytes = self._convertToAsn1Signature(signature)
        hash         = Digest.SHA256(data)

        return self.ec.verify_dsa_asn1(hash, asn1SigBytes)

    def getRawKey(self):
        return self.rawPublicKey

    def getFingerprint(self):
        digest = Digest.SHA256(self.rawPublicKey)
        assert(len(digest) == 32)
        s = b2a_base32(digest).lower()[:25]
        return "%s.%s.%s.%s.%s" % (s[:5],s[5:10],s[10:15],s[15:20],s[20:25])

    def _constructEcFromRawKey(self, rawPublicKey):
        assert(len(rawPublicKey) == 64)
        bytes1         = a2b_hex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
        asn1KeyBytes   = bytes1 + rawPublicKey
        pemPubKeyBytes = PEMEncoder(asn1KeyBytes).encode("PUBLIC KEY")

        return EC.load_pub_key_bio(BIO.MemoryBuffer(pemPubKeyBytes))

    def _convertToAsn1Signature(self, signature):
        assert(len(signature) == 64)
        asn1R = toAsn1IntBytes(signature[:32])
        asn1S = toAsn1IntBytes(signature[32:])
        # Add ASN1 Type=2(int), and Length fields
        asn1R = bytearray([2]) + asn1Length(len(asn1R)) + asn1R
        asn1S = bytearray([2]) + asn1Length(len(asn1S)) + asn1S
        # Add ASN1 Type=0x30(Sequence) and Length fields
        asn1ECSigBytes = bytearray([0x30]) +\
                         asn1Length(len(asn1R+asn1S)) + asn1R + asn1S
        return asn1ECSigBytes

    def __str__(self):
        return self.getFingerprint()
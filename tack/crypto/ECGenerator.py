from M2Crypto import EC, BIO
from tack.crypto.ASN1 import ASN1Parser, fromAsn1IntBytes
from tack.crypto.ECPrivateKey import ECPrivateKey
from tack.crypto.ECPublicKey import ECPublicKey
from tack.util.PEMDecoder import PEMDecoder

class ECGenerator:

    def generateECKeyPair(self):
        # Generate M2Crypto.EC.EC object
        ec = EC.gen_params(EC.NID_X9_62_prime256v1)
        ec.gen_key()

        rawPrivateKey, rawPublicKey = self._constructRawKeysFromEc(ec)

        return ECPublicKey(rawPublicKey, ec), ECPrivateKey(rawPrivateKey, rawPublicKey, ec)

    def _constructRawKeysFromEc(self, ec):
        derEncodedKeys = self._getDerEncodedKeysFromEc(ec)
        parser         = ASN1Parser(derEncodedKeys)

        # The private key is stored as an ASN.1 integer which may
        # need to have zero padding removed (if 33 bytes) or added
        # (if < 32 bytes):
        rawPrivateKey = parser.getChild(1).value
        rawPrivateKey = fromAsn1IntBytes(rawPrivateKey, 32)

        # There is a 00 04 byte prior to the 64-byte public key
        # I'm not sure why M2Crypto has the 00 byte there?,
        # some ASN1 thing - the 04 byte signals "uncompressed"
        # per SECG.  Anyways, strip both those bytes off ([2:])
        rawPublicKey = parser.getChild(3).getTagged().value[2:]

        assert(len(rawPrivateKey) == 32)
        assert(len(rawPublicKey) == 64)

        return rawPrivateKey, rawPublicKey

    def _getDerEncodedKeysFromEc(self, ec):
        # Get the ASN.1 ECPrivateKey for the object
        bio = BIO.MemoryBuffer()
        ec.save_key_bio(bio, cipher=None)
        pemEncodedKeys = bio.getvalue()

        return PEMDecoder(pemEncodedKeys).decode("EC PRIVATE KEY")


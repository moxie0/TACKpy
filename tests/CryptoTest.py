import unittest
from TACKpy.ecdsa_wrappers import ecdsa256Verify
from tack.compat import a2b_hex
from tack.crypto.AES import AES
from tack.crypto.ASN1 import asn1Length, toAsn1IntBytes, fromAsn1IntBytes
from tack.crypto.ECDSA import ec256Generate, ecdsa256Sign

class CryptoTest(unittest.TestCase):

    def test_AES(self):
        key = a2b_hex("c286696d887c9aa0611bbb3e2025a45a")
        IV = a2b_hex("562e17996d093d28ddb3ba695a2e6f58")
        plaintext = a2b_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        ciphertext = a2b_hex("d296cd94c2cccf8a3a863028b5e1dc0a7586602d253cfff91b8266bea6d61ab1")

        assert(AES(key, IV).encrypt(plaintext) == ciphertext)
        assert(AES(key, IV).decrypt(ciphertext) == plaintext)

    def test_ECDSA(self):
        privateKey, publicKey = ec256Generate()
        data = bytearray([0,1,2,3])
        badData = bytearray([0,1,2,4])
        signature = ecdsa256Sign(privateKey, publicKey, data)
        assert(ecdsa256Verify(publicKey, data, signature))
        assert(not ecdsa256Verify(publicKey, badData, signature))

    def test_ASN1(self):
        assert(asn1Length(7) == bytearray([7]))
        assert(asn1Length(0x7F) == bytearray([0x7F]))
        assert(asn1Length(0x80) == bytearray([0x81,0x80]))
        assert(asn1Length(0x81) == bytearray([0x81,0x81]))
        assert(asn1Length(0xFF) == bytearray([0x81,0xFF]))
        assert(asn1Length(0x0100) == bytearray([0x82,0x01,0x00]))
        assert(asn1Length(0x0101) == bytearray([0x82,0x01,0x01]))
        assert(asn1Length(0xFFFF) == bytearray([0x82,0xFF,0xFF]))

        assert(toAsn1IntBytes(bytearray([0xFF])) == bytearray([0x00,0xFF]))
        assert(toAsn1IntBytes(bytearray([0x7F])) == bytearray([0x7F]))
        assert(toAsn1IntBytes(bytearray([0x00])) == bytearray([0x00]))
        assert(toAsn1IntBytes(bytearray([0x00,0x00])) == bytearray([0x00]))
        assert(toAsn1IntBytes(bytearray([0x00,0x01])) == bytearray([0x01]))
        assert(toAsn1IntBytes(bytearray([0,0xFF])) == bytearray([0,0xFF]))
        assert(toAsn1IntBytes(bytearray([0,0,0,0xFF])) == bytearray([0,0xFF]))
        assert(toAsn1IntBytes(bytearray([0,0,0,1,1])) == bytearray([1,1]))

        assert(bytearray([0xFF]) == fromAsn1IntBytes(bytearray([0x00,0xFF]),1))
        assert(bytearray([0x7F]) == fromAsn1IntBytes(bytearray([0x7F]),1))
        assert(bytearray([0x00]) == fromAsn1IntBytes(bytearray([0x00]),1))
        assert(bytearray([0x00,0x00]) == fromAsn1IntBytes(bytearray([0x00]),2))
        assert(bytearray([0x00,0x01]) == fromAsn1IntBytes(bytearray([0x01]),2))
        assert(bytearray([0,0xFF]) == fromAsn1IntBytes(bytearray([0,0xFF]),2))
        assert(bytearray([0,0,0,0xFF]) == fromAsn1IntBytes(bytearray([0,0xFF]),4))
        assert(bytearray([0,0,0,1,1]) == fromAsn1IntBytes(bytearray([1,1]),5))

if __name__ == '__main__':
    unittest.main()
# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

import unittest
from tack.compat import a2b_hex
from tack.crypto.AES import AES
from tack.crypto.ASN1 import asn1Length, toAsn1IntBytes, fromAsn1IntBytes
from tack.crypto.ECGenerator import ECGenerator

class CryptoTest(unittest.TestCase):

    def test_AES(self):
        key = a2b_hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
        IV = a2b_hex("000102030405060708090A0B0C0D0E0F")
        plaintext = a2b_hex("6bc1bee22e409f96e93d7e117393172a")
        ciphertext = a2b_hex("f58c4c04d6e5f1ba779eabfb5f7bfbd6")

        assert(AES.create(key, IV).encrypt(plaintext) == ciphertext)
        assert(AES.create(key, IV).decrypt(ciphertext) == plaintext)

    def test_ECDSA(self):
        publicKey, privateKey = ECGenerator().generateECKeyPair()
        data = bytearray([0,1,2,3])
        badData = bytearray([0,1,2,4])

        signature = privateKey.sign(data)
        assert(publicKey.verify(data, signature))
        assert(not publicKey.verify(badData, signature))

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
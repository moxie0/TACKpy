# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

import unittest
from tack.compat import a2b_hex
from tack.compat import a2b_base64
from tack.compat import b2a_hex
from tack.compat import b2a_base64
from tack.compat import bytesToStr

class CompatTest(unittest.TestCase):

    def test_Compat(self):
        assert(isinstance(a2b_hex("00"), bytearray))
        assert(a2b_hex("0102cdef") == bytearray([0x01,0x02,0xcd,0xef]))
        assert(a2b_hex("0102CDEF") == bytearray([0x01,0x02,0xcd,0xef]))
        try:
            assert(a2b_hex("c0102cdef") == bytearray([0x01,0x02,0xcd,0xef]))
            assert False
        except SyntaxError:
            pass
        try:
            assert(a2b_hex("xx0102cdef") == bytearray([0x01,0x02,0xcd,0xef]))
            assert False
        except SyntaxError:
            pass

        assert(isinstance(a2b_base64("0000"), bytearray))
        assert(a2b_base64("Zm9vYg==") == bytearray(b"foob"))

        assert(b2a_hex(bytearray([0x01,0x02,0xcd,0xef])) == "0102cdef")
        assert(b2a_hex(bytearray([0x00])) == "00")
        assert(b2a_hex(bytearray([0xFF])) == "ff")

        assert(b2a_base64(bytearray(b"foob")) == "Zm9vYg==\n")
        assert(b2a_base64(bytearray(b"fooba")) == "Zm9vYmE=\n")
        assert(b2a_base64(bytearray(b"foobar")) == "Zm9vYmFy\n")

        assert(bytesToStr(bytearray(b"abcd123")) == "abcd123")

if __name__ == '__main__':
    unittest.main()
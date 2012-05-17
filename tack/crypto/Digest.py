# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

import hashlib
import hmac
from tack.compat import compat26Str

class Digest:
    @staticmethod
    def SHA256(b):
        "Return a 32-byte bytearray which is the SHA256 of input bytearray."
        return bytearray(hashlib.sha256(compat26Str(b)).digest())

    @staticmethod
    def HMAC_SHA256(k, b):
        """Return a 32-byte bytearray which is HMAC-SHA256 of key and input."""
        return bytearray(hmac.new(bytes(k), bytes(b), hashlib.sha256).digest())

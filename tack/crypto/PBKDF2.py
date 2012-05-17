# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

from tack.crypto.Digest import Digest

class PBKDF2:

    @staticmethod
    def _xorbytes(s1, s2):
        return bytearray([a^b for a,b in zip(s1,s2)])

    # Uses PBKDF2-HMAC-SHA256 to produce a 32-byte key
    @staticmethod
    def hmac_sha256(password, salt, iter_count):
        m = salt + bytearray([0,0,0,1])
        result = bytearray(32)
        for c in range(iter_count):
            m = Digest.HMAC_SHA256(bytearray(password, "ascii"), m)
            result = PBKDF2._xorbytes(m, result)

        return result

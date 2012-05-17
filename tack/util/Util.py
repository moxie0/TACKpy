# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

from tack.compat import b2a_hex

class Util:
    @staticmethod
    def writeBytes(b):
        """Write hex-encoded byte array with 16 bytes (32 chars) per line"""
        s = b2a_hex(b)
        retVal = ""
        while s:
            retVal += s[:32]
            s = s[32:]
            if len(s):
                retVal += "\n                 "
        return retVal

    @staticmethod
    def constTimeCompare(a, b):
        """Compare two sequences of integer (eg bytearrays) without a timing leak.

        This function is secure when comparing against secret values, such as
        passwords, MACs, etc., where a more naive, early-exit comparison loop
        would leak information that could be used to extract the secret.
        """
        if len(a) != len(b):
            return False
        result = 0
        for x in range(len(a)):
            result |= a[x]^b[x]
        if result:
            return False
        return True

from tack.compat import b2a_base32
from tack.crypto.Digest import Digest

class TackId():

    def __init__(self, public_key):
        self.id = self._hashToTackId(Digest.SHA256(public_key))

    def getId(self):
        return self.id

    def _hashToTackId(self, b):
        assert(len(b) == 32)
        s = b2a_base32(b).lower()[:25]
        return "%s.%s.%s.%s.%s" % (s[:5],s[5:10],s[10:15],s[15:20],s[20:25])

    def __str__(self):
        return self.id
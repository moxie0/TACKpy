# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

from tack.compat import b2a_base32
from tack.crypto.Digest import Digest
from tack.crypto.openssl.OpenSSL import openssl as o
from tack.crypto.openssl.OpenSSL import bytesToC


class OpenSSL_ECPublicKey:

    def __init__(self, rawPublicKey, ec_key=None):
        self.ec_key = None # In case of early destruction
        assert(rawPublicKey is not None)
        assert(len(rawPublicKey) == 64)

        self.rawPublicKey = rawPublicKey
        if ec_key:
            self.ec_key = o.EC_KEY_dup(ec_key)
        else:
            self.ec_key =  self._constructEcFromRawKey(self.rawPublicKey)

    def __del__(self):
        o.EC_KEY_free(self.ec_key)

    def verify(self, data, signature):
        assert(len(signature) == 64)
        ecdsa_sig = None

        try:
            # Create ECDSA_SIG
            ecdsa_sig = o.ECDSA_SIG_new()
            rBuf = bytesToC(signature[ : 32])
            sBuf = bytesToC(signature[32 : ])
            o.BN_bin2bn(rBuf, 32, ecdsa_sig.contents.r)
            o.BN_bin2bn(sBuf, 32, ecdsa_sig.contents.s)
            
            # Hash and verify ECDSA
            hashBuf = bytesToC(Digest.SHA256(data))
            retval = o.ECDSA_do_verify(hashBuf, 32, ecdsa_sig, self.ec_key)
            if retval == 1:
                return True
            elif retval == 0:
                return False
            else:
                assert(False)
        finally:
            if ecdsa_sig:
                o.ECDSA_SIG_free(ecdsa_sig)

    def getRawKey(self):
        return self.rawPublicKey

    def getFingerprint(self):
        digest = Digest.SHA256(self.rawPublicKey)
        assert(len(digest) == 32)
        s = b2a_base32(digest).lower()[:25]
        return "%s.%s.%s.%s.%s" % (s[:5],s[5:10],s[10:15],s[15:20],s[20:25])

    def _constructEcFromRawKey(self, rawPublicKey):
        ec_key, ec_group, ec_point = None, None, None

        try:
            ec_key = o.EC_KEY_new_by_curve_name(o.OBJ_txt2nid(b"prime256v1"))
            ec_group = o.EC_GROUP_new_by_curve_name(o.OBJ_txt2nid(b"prime256v1"))
            ec_point = o.EC_POINT_new(ec_group)
            
            # Add 0x04 byte to signal "uncompressed" public key
            pubBuf = bytesToC(bytearray([0x04]) + rawPublicKey)
            o.EC_POINT_oct2point(ec_group, ec_point, pubBuf, 65, None)                
            o.EC_KEY_set_public_key(ec_key, ec_point)
            return o.EC_KEY_dup(ec_key)
        finally:
            if ec_key:
                o.EC_KEY_free(ec_key)

            if ec_group:
                o.EC_KEY_free(ec_group)

            if ec_point:
                o.EC_POINT_free(ec_point)

    def __str__(self):
        return self.getFingerprint()
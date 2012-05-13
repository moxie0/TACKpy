from .openssl.OpenSSL import openssl as o
from .openssl.OpenSSL_ECPublicKey import OpenSSL_ECPublicKey
from tack.util.PEMEncoder import PEMEncoder

class ECPublicKey:

    @staticmethod
    def new(rawPublicKey):
        if o.enabled:
            return OpenSSL_ECPublicKey(rawPublicKey)
        assert(False)

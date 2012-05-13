from .openssl.OpenSSL_ECPrivateKey import OpenSSL_ECPrivateKey
from .openssl.OpenSSL import openssl as o

class ECPrivateKey:

    @staticmethod
    def new(rawPrivateKey, rawPublicKey):
        if o.enabled:
            return OpenSSL_ECPrivateKey(rawPrivateKey, rawPublicKey)
        assert(False)

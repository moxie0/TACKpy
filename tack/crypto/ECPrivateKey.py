from .openssl.OpenSSL_ECPrivateKey import OpenSSL_ECPrivateKey
from .openssl.OpenSSL import openssl as o
from tack.util.PEMEncoder import PEMEncoder

class ECPrivateKey:
    
    @staticmethod
    def generateECKeyPair():
        if o.enabled:
            return OpenSSL_ECPrivateKey.generateECKeyPair()
        assert(False)

    @staticmethod
    def new(rawPrivateKey, rawPublicKey):
        if o.enabled:
            return OpenSSL_ECPrivateKey(rawPrivateKey, rawPublicKey)
        assert(False)

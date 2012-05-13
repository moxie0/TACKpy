from .openssl.OpenSSL_ECGenerator import OpenSSL_ECGenerator
from .openssl.OpenSSL import openssl as o

class ECGenerator:
    
    @staticmethod
    def generateECKeyPair():
        if o.enabled:
            return OpenSSL_ECGenerator.generateECKeyPair()
        assert(False)

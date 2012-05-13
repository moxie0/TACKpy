from .openssl.OpenSSL_ECGenerator import OpenSSL_ECGenerator
from .python.Python_ECGenerator import Python_ECGenerator
from .openssl.OpenSSL import openssl as o

class ECGenerator:
    
    @staticmethod
    def generateECKeyPair():
        if o.enabled:
            return OpenSSL_ECGenerator.generateECKeyPair()
        else:
            return Python_ECGenerator.generateECKeyPair()

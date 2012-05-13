from .openssl.OpenSSL import openssl
from .openssl.OpenSSL_AES import OpenSSL_AES

class AES:

    @staticmethod
    def new(key, IV):
        if openssl.enabled:
            return OpenSSL_AES(key, IV)
        assert(False)

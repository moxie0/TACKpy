# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

from .python.Python_ECPrivateKey import Python_ECPrivateKey
from .openssl.OpenSSL_ECPrivateKey import OpenSSL_ECPrivateKey
from .openssl.OpenSSL import openssl as o

class ECPrivateKey:

    @staticmethod
    def create(rawPrivateKey, rawPublicKey):
        if o.enabled:
            return OpenSSL_ECPrivateKey(rawPrivateKey, rawPublicKey)
        else:
            return Python_ECPrivateKey(rawPrivateKey, rawPublicKey)

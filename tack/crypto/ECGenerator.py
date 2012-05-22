# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

from tack.crypto.openssl.OpenSSL_ECGenerator import OpenSSL_ECGenerator
from tack.crypto.python.Python_ECGenerator import Python_ECGenerator
from tack.crypto.openssl.OpenSSL import openssl as o

class ECGenerator:
    
    @staticmethod
    def generateECKeyPair():
        if o.enabled:
            return OpenSSL_ECGenerator.generateECKeyPair()
        else:
            return Python_ECGenerator.generateECKeyPair()

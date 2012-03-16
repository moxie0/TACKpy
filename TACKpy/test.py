# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

from .numbertheory import testNumberTheory
from .ellipticcurve import testEllipticCurve
from .ecdsa import testECDSA
from .ecdsa_wrappers import testECDSAWrappers
from .rijndael import testRijndael
from .aes_wrappers import testAES
from .cryptomath import testOsUrandom
from .compat import testCompat
from .asn1 import testASN1
from .time_funcs import testTime
from .tack_structures import testTACKStructures
from .tackid import testTACKID
from .ssl_cert import testSSLCert
from .keyfile import testKeyFile

################ TEST ###

def selfTest():
    assert(testNumberTheory() == 1)
    assert(testEllipticCurve() == 1)
    assert(testECDSA() == 1)
    assert(testECDSAWrappers() == 1)
    assert(testRijndael() == 1)
    assert(testAES() == 1)
    assert(testOsUrandom() == 1)
    assert(testASN1() == 1)
    assert(testCompat() == 1)
    assert(testTime() == 1)
    assert(testTACKStructures() == 1)
    assert(testTACKID() == 1)
    assert(testSSLCert() == 1)
    assert(testKeyFile() == 1)
    return 1

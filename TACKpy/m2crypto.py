# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

################ M2CRYPTO ###

try:
    from M2Crypto import EC, BIO, m2
    m2cryptoLoaded = True

except ImportError:
    m2cryptoLoaded = False
        
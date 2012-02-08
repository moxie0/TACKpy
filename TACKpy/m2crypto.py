# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

################ M2CRYPTO ###

try:
    from M2Crypto import EC, BIO, m2
    m2cryptoLoaded = True

except ImportError:
    m2cryptoLoaded = False
except:
    # Most likely ImportError, but I've seen AttributeError from what 
    # might've been an incorrectly installed M2Crypto (on AWS), so
    # let's just swallow everything...    
    m2cryptoLoaded = False
    import sys
    sys.stderr.write("Error importing M2Crypto?! \n")

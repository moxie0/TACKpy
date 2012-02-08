# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

################ CONSTANTS ###

class TACK_Key_Type:
    v1 = 1
    strings = (None, "v1")

class TACK_Sig_Type:
    v1_key = 1
    v1_cert = 2
    all = (v1_key, v1_cert)
    strings = (None, "v1_key", "v1_cert")
    
class TACK_Extension_Type:
    v1 = 1
    strings = (None, "v1")

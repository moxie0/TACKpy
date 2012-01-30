
from compat import *

################ MISC ###

# Helper function used by structures to print out their binary elements
def writeBytes(b):
    """Write hex-encoded byte array with 16 bytes (32 chars) per line"""
    s = b2a_hex(b)
    retVal = ""
    while s:
        retVal += s[:32]
        s = s[32:]
        if len(s):
            retVal += "\n                   "
    return retVal
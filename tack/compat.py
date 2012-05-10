# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

################ COMPAT ###
"""These functions abstract away the differences between Python 2 and 3.
"""

import sys, binascii, base64

if sys.version_info >= (3,0):
    def raw_input(s):
        return input(s)
    
    # So, the python3 binascii module deals with bytearrays, and python2
    # deals with strings...  I would rather deal with the "a" part as
    # strings, and the "b" part as bytearrays, regardless of python version,
    # so...
    def a2b_hex(s):
        try:
            b = bytearray(binascii.a2b_hex(bytearray(s, "ascii")))
        except Exception as e:
            raise SyntaxError("base16 error: %s" % e) 
        return b  

    def a2b_base64(s):
        try:
            b = bytearray(binascii.a2b_base64(bytearray(s, "ascii")))
        except Exception as e:
            raise SyntaxError("base64 error: %s" % e)
        return b

    def b2a_hex(b):
        return binascii.b2a_hex(b).decode("ascii")    
            
    def b2a_base64(b):
        return binascii.b2a_base64(b).decode("ascii") 

    def b2a_base32(b):
        return base64.b32encode(b).decode("ascii")
        
    def bytesToStrAscii(b):
        return str(b, "ascii")  
    
    def compat26Str(x): return x

else:
    # Python 2.6 requires strings instead of bytearrays in a couple places,
    # so we define this function so it does the conversion if needed.
    if sys.version_info < (2,7):
        def compat26Str(x): return str(x)
    else:
        def compat26Str(x): return x
        
 
    def a2b_hex(s):
        try:
            b = bytearray(binascii.a2b_hex(s))
        except Exception as e:
            raise SyntaxError("base16 error: %s" % e)
        return b

    def a2b_base64(s):
        try:
            b = bytearray(binascii.a2b_base64(s))
        except Exception as e:
            raise SyntaxError("base64 error: %s" % e)
        return b
        
    def b2a_hex(b):
        return binascii.b2a_hex(compat26Str(b))
        
    def b2a_base64(b):
        return binascii.b2a_base64(compat26Str(b))
        
    def b2a_base32(b):
        return base64.b32encode(str(b))        
        
    def bytesToStrAscii(b):
        return str(b)

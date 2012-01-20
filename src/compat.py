################ COMPAT ###
"""These functions abstract away the differences between Python 2 and 3.
"""

import sys, binascii
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
        
    def bytesToStrAscii(b):
        return str(b, "ascii")  
         
else:
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
        return binascii.b2a_hex(b)
        
    def b2a_base64(b):
        return binascii.b2a_base64(b)
        
    def bytesToStrAscii(b):
        return str(b)


def testCompat():
    print("Testing COMPAT")    
    assert(isinstance(a2b_hex("00"), bytearray))
    assert(a2b_hex("0102cdef") == bytearray([0x01,0x02,0xcd,0xef]))
    assert(a2b_hex("0102CDEF") == bytearray([0x01,0x02,0xcd,0xef]))
    try:
        assert(a2b_hex("c0102cdef") == bytearray([0x01,0x02,0xcd,0xef]))
        assert(False)
    except SyntaxError:
        pass
    try:
        assert(a2b_hex("xx0102cdef") == bytearray([0x01,0x02,0xcd,0xef]))
        assert(False)
    except SyntaxError:
        pass

    assert(isinstance(a2b_base64("0000"), bytearray))
    
    assert(b2a_hex(bytearray([0x01,0x02,0xcd,0xef])) == "0102cdef")
    assert(b2a_hex(bytearray([0x00])) == "00")
    assert(b2a_hex(bytearray([0xFF])) == "ff")

    assert(b2a_base64(bytearray(b"foob")) == "Zm9vYg==\n")
    assert(b2a_base64(bytearray(b"fooba")) == "Zm9vYmE=\n")
    assert(b2a_base64(bytearray(b"foobar")) == "Zm9vYmFy\n")

    assert(bytesToStrAscii(bytearray(b"abcd123")) == "abcd123") 
    return 1
    
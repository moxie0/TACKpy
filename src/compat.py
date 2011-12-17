################ COMPAT ###
import sys, binascii
if sys.version_info >= (3,0):
    def raw_input(s):
        return input(s)
    
    def a2b_hex(s):
        b = binascii.a2b_hex(bytearray(s, "ascii"))  
        return b  
    def b2a_hex(b):
        return binascii.b2a_hex(b).decode("ascii")        
    def b2a_base64(b):
        return binascii.b2a_base64(b).decode("ascii") 
        
    def bytesToStr(b):
        return str(b, "ascii")  
         
else:
    def a2b_hex(s):
        return binascii.a2b_hex(s)
    def b2a_hex(b):
        return binascii.b2a_hex(b)
    def b2a_base64(b):
        return binascii.b2a_base64(b)
        
    def bytesToStr(b):
        return str(b)



from struct_parser import *
from cryptomath import *

################ ASN1 PARSER ###
# Returns bytearray encoding an ASN1 length field
# Assumes maximum of 2-byte length
def asn1Length(x):
    if x < 128:
        return bytearray([x])
    if x < 256:
        return bytearray([0x81,x])  
    if x < 65536:
        return bytearray([0x82, int(x//256), x % 256])  
    assert(False)

def asn1Int(x):
    """Converts a Python integer to a bytearray containing ASN.1 integer"""
    b = numberToBytes(x)
    # Strip leading zeros
    while b[0] == 0 and len(b)>1:
        b = b[1:]
    # Add a leading zero if high bit is set
    if b[0] & 0x80:
        b = bytearray([0]) + b
    # Add ASN.1 type and length fields
    b = bytearray([2]) + asn1Length(len(b)) + b
    return b
            
#Takes a byte array which has a DER TLV field at its head
class ASN1Parser:
    def __init__(self, bytes, offset = 0):
        p = Parser(bytes)
        self.type = p.getInt(1) #skip Type

        #Get Length
        self.length = self._getASN1Length(p)
        
        # Header length is however many bytes read so far
        self.headerLength = p.index        

        #Get Value
        self.value = p.getBytes(self.length)
        
        # This value tracks the offset of this TLV field
        # in some enclosing structure (ie an X.509 cert) 
        self.offset = offset
        

    #Assuming this is a sequence...
    def getChild(self, which):
        p = Parser(self.value)
        for x in range(which+1):
            if p.index == len(p.bytes):
                return None
            markIndex = p.index
            p.getInt(1) #skip Type
            length = self._getASN1Length(p)
            p.getBytes(length)
        return ASN1Parser(p.bytes[markIndex : p.index], \
                            self.offset + self.headerLength + markIndex)

    #Assuming this is a tagged element...
    def getTagged(self):
        return ASN1Parser(self.value, self.offset + self.headerLength)

    def getTotalLength(self):
        return self.headerLength + self.length
        
    def getTotalBytes(self):
        return bytearray([self.type]) + asn1Length(self.length) + self.value

    #Decode the ASN.1 DER length field
    def _getASN1Length(self, p):
        firstLength = p.getInt(1)
        if firstLength<=127:
            lengthLength = 1
            return firstLength
        else:
            lengthLength = firstLength & 0x7F
            return p.getInt(lengthLength)

        


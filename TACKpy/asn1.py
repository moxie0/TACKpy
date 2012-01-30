
from .struct_parser import *
from .cryptomath import *

################ ASN1 ###
def asn1Length(x):
    """Return a bytearray encoding an ASN1 length field based on input length.
    
    The ASN.1 length field is itself variable-length, depending on whether
    the length can be encoded in 7 bits.  If so, the length is encoded in a
    single byte with the high bit cleared.  Otherwise, the first byte's
    high bit is set, and the remaining 7 bits encode the number of following
    bytes needed to encode the length as a big-endian integer.
    
    The function is currently limited to input lengths < 65536.
    
    This function is useful when kludging together ASN.1 data structures.
    """
    if x < 128:
        return bytearray([x])
    if x < 256:
        return bytearray([0x81,x])  
    if x < 65536:
        return bytearray([0x82, int(x//256), x % 256])  
    assert(False)

def toAsn1IntBytes(b):
    """Return a bytearray containing ASN.1 integer based on input bytearray.
    
    An ASN.1 integer is a big-endian sequence of bytes, with excess zero bytes
    at the beginning removed.  However, if the high bit of the first byte 
    would be set, a zero byte is prepended.  Note that the ASN.1 type/len
    fields are NOT added by this function.
    """    
    # Strip leading zeros
    while b[0] == 0 and len(b)>1:
        b = b[1:]
    # Add a leading zero if high bit is set
    if b[0] & 0x80:
        b = bytearray([0]) + b
    return b    

def fromAsn1IntBytes(b, size):
    """Return a bytearray of "size" bytes representing a big-endian integer 
    by converting the input bytearray's ASN.1 integer.
    
    An ASN.1 integer is a big-endian sequence of bytes, with excess zero bytes
    at the beginning removed.  However, if the high bit of the first byte 
    would be set, a zero byte is prepended.  Note that the ASN.1 type/len
    fields are NOT removed by this function.
    
    Raises SyntaxError.
    """        
    if len(b) > size+1:
        raise SyntaxError("ASN.1 integer is too big")
    if len(b)==size+1: # This can occur if the integer's high bit was set
        if b[0] != 0:
            raise SyntaxError("ASN.1 integer too big")
        if (b[1] & 0x80) == 0:
            raise SyntaxError("ASN.1 integer has excess zero padding")
        return b[1:]
    else:
        # Prepend zero bytes if needed to reach "size" bytes
        return bytearray([0]*(size-len(b))) + b
            
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

        

def testASN1():
    print("Testing ASN1")
    assert(asn1Length(7) == bytearray([7]))
    assert(asn1Length(0x7F) == bytearray([0x7F]))
    assert(asn1Length(0x80) == bytearray([0x81,0x80]))
    assert(asn1Length(0x81) == bytearray([0x81,0x81]))
    assert(asn1Length(0xFF) == bytearray([0x81,0xFF]))
    assert(asn1Length(0x0100) == bytearray([0x82,0x01,0x00]))
    assert(asn1Length(0x0101) == bytearray([0x82,0x01,0x01]))
    assert(asn1Length(0xFFFF) == bytearray([0x82,0xFF,0xFF]))    
    
    assert(toAsn1IntBytes(bytearray([0xFF])) == bytearray([0x00,0xFF]))
    assert(toAsn1IntBytes(bytearray([0x7F])) == bytearray([0x7F]))
    assert(toAsn1IntBytes(bytearray([0x00])) == bytearray([0x00]))
    assert(toAsn1IntBytes(bytearray([0x00,0x00])) == bytearray([0x00]))
    assert(toAsn1IntBytes(bytearray([0x00,0x01])) == bytearray([0x01]))
    assert(toAsn1IntBytes(bytearray([0,0xFF])) == bytearray([0,0xFF]))
    assert(toAsn1IntBytes(bytearray([0,0,0,0xFF])) == bytearray([0,0xFF]))
    assert(toAsn1IntBytes(bytearray([0,0,0,1,1])) == bytearray([1,1]))    

    assert(bytearray([0xFF]) == fromAsn1IntBytes(bytearray([0x00,0xFF]),1))
    assert(bytearray([0x7F]) == fromAsn1IntBytes(bytearray([0x7F]),1))
    assert(bytearray([0x00]) == fromAsn1IntBytes(bytearray([0x00]),1))
    assert(bytearray([0x00,0x00]) == fromAsn1IntBytes(bytearray([0x00]),2))
    assert(bytearray([0x00,0x01]) == fromAsn1IntBytes(bytearray([0x01]),2))
    assert(bytearray([0,0xFF]) == fromAsn1IntBytes(bytearray([0,0xFF]),2))
    assert(bytearray([0,0,0,0xFF]) == fromAsn1IntBytes(bytearray([0,0xFF]),4))
    assert(bytearray([0,0,0,1,1]) == fromAsn1IntBytes(bytearray([1,1]),5))
    #!!! Add testing for ASN1Parser
    return 1
    
    

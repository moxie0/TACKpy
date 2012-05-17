# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

class TlsStructure:
    def __init__(self, bytes):
        self.bytes = bytes
        self.index = 0

    def getInt(self, elementLength):
        """Reads an integer of 'length' bytes"""
        if self.index + elementLength > len(self.bytes):
            raise SyntaxError("Reading %s at index %s but only %s bytes remaining." \
                              % (elementLength, self.index, len(self.bytes)))
        x = 0
        for count in range(elementLength):
            x <<= 8
            x |= self.bytes[self.index]
            self.index += 1
        return x

    def getBytes(self, elementLength):
        """Reads some number of bytes as determined by 'elementLength'"""
        bytes = self.bytes[self.index : self.index + elementLength]
        self.index += elementLength
        return bytes

    def getVarSeqBytes(self, elementLength, lengthLength):
        dataLength = self.getInt(lengthLength)
        if dataLength % elementLength != 0:
            raise SyntaxError()
        return [self.getBytes(elementLength) for x in\
                range(dataLength//elementLength)]

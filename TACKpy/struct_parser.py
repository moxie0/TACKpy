# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

from .compat import *

################ STRUCT PARSER ###

class Writer:
    def __init__(self, totalLength):
        self.index = 0
        self.bytes = bytearray(totalLength)

    def add(self, x, elementLength):
        """Writes 'elementLength' bytes, input is either an integer
         (written as big-endian) or a sequence of bytes"""
        if isinstance(x, int):
            assert(x >= 0 and x < 2**(8*elementLength))
            newIndex = self.index + elementLength-1
            while newIndex >= self.index:
                self.bytes[newIndex] = x & 0xFF
                x >>= 8
                newIndex -= 1
        else:
            assert(len(x) == elementLength)
            for i in range(elementLength):
                self.bytes[self.index + i] = x[i]                
        self.index += elementLength

    def addVarSeq(self, seq, elementLength, lengthLength):
        """Writes a sequence of elements prefixed by a 
        total-length field of lengthLength bytes"""
        self.add(len(seq)*elementLength, lengthLength)
        for e in seq:
            self.add(e, elementLength)

class Parser:
    def __init__(self, bytes):
        self.bytes = bytes
        self.index = 0

    def getInt(self, elementLength):
        """Reads an integer of 'length' bytes"""
        if self.index + elementLength > len(self.bytes):
            raise SyntaxError()
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
        return [self.getBytes(elementLength) for x in \
                range(dataLength//elementLength)]



# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

class TlsStructureWriter:
    def __init__(self, totalLength):
        self.index = 0
        self.bytes = bytearray(totalLength)

    def add(self, x, elementLength):
        """Writes 'elementLength' bytes, input is either an integer
         (written as big-endian) or a sequence of bytes"""
        if isinstance(x, int):
            assert(0 <= x < 2**(8*elementLength))
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

    def getBytes(self):
        assert(self.index == len(self.bytes))
        return self.bytes
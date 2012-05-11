from tack.crypto.ECPublicKey import ECPublicKey
from tack.tls.TlsStructure import TlsStructure
from tack.tls.TlsStructureWriter import TlsStructureWriter
from tack.util.PEMDecoder import PEMDecoder
from tack.util.PEMEncoder import PEMEncoder

class TackBreakSig(TlsStructure):
    LENGTH = 128

    def __init__(self, data=None):
        TlsStructure.__init__(self, data)

        if data is not None and len(data) != TackBreakSig.LENGTH:
            raise SyntaxError("Break signature is the wrong size. Is %s and should be %s." % (len(data), TackBreakSig.LENGTH))

        if data is not None:
            self.public_key = ECPublicKey(self.getBytes(64))
            self.signature  = self.getBytes(64)

            if self.index != len(data):
                raise SyntaxError("Excess bytes in TACK_Break_Sig")

    @classmethod
    def createFromPem(cls, data):
        return cls(PEMDecoder(data).getDecoded("TACK BREAK SIG"))

    @classmethod
    def createFromPemList(cls, data):
        """Parse a string containing a sequence of PEM Break Sigs.

        Raise a SyntaxError if input is malformed.
        """
        breakSigs = []
        bList = PEMDecoder(data).getDecodedList("TACK BREAK SIG")
        for b in bList:
            breakSigs.append(TackBreakSig(b))

        return breakSigs

    @classmethod
    def create(cls, public_key, private_key):
        tackBreakSig            = cls()
        tackBreakSig.public_key = public_key
        tackBreakSig.signature  = private_key.getSignature(bytearray("tack_break_sig", "ascii"))

        return tackBreakSig

    def serialize(self):
        """Return a bytearray containing the TACK_Break_Sig."""
        w = TlsStructureWriter(TackBreakSig.LENGTH)
        w.add(self.public_key.getRawKey(), 64)
        w.add(self.signature, 64)
        assert(w.index == len(w.bytes))
        return w.getBytes()

    def serializeAsPem(self):
        return PEMEncoder(self.serialize()).getEncoded("TACK BREAK SIG")

    def getTackId(self):
        return str(self.public_key)

    def _verifySignature(self):
        return self.public_key.verify(bytearray("tack_break_sig"), self.signature)

    def __str__(self):
        """Return a readable string describing this TACK_Break_Sig.
        Used by the "TACK view" command to display TACK objects."""
        return "Breaks TACK ID = %s\n" % self.getTackId()

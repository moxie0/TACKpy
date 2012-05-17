# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

from tack.compat import a2b_hex, bytesToStr
from tack.crypto.ASN1 import ASN1Parser, asn1Length
from tack.crypto.Digest import Digest
from tack.structures.TackExtension import TackExtension
from tack.util.PEMDecoder import PEMDecoder
from tack.util.PEMEncoder import PEMEncoder
from tack.util.Time import Time
from tack.util.Util import Util

class TlsCertificate:

    OID_TACK = bytearray(b"\x2B\x06\x01\x04\x01\x82\xB0\x34\x01")

    def __init__(self, data=None):
        if data is None:
            return
        #self.key_sha256 = bytearray(32)
        #self.cert_sha256 = bytearray(32)
        self.notAfter = 0
        
        # Below values are populated for TACK certs
        self.tackExt = None
        
        # Below values hold cert contents excluding TACK stuff
        self.preExtBytes = None
        self.extBytes = None
        self.postExtBytes = None

        p = ASN1Parser(data)

        #Get the tbsCertificate
        tbsCertificateP = p.getChild(0)

        #Is the optional version field present?
        #This determines which index the key is at
        if tbsCertificateP.value[0]==0xA0:
            subjectPublicKeyInfoIndex = 6
            validityIndex = 4
        else:
            subjectPublicKeyInfoIndex = 5
            validityIndex = 3
            #Get the subjectPublicKeyInfo
        spkiP = tbsCertificateP.getChild(subjectPublicKeyInfoIndex)

        #Parse the notAfter time
        validityP = tbsCertificateP.getChild(validityIndex)
        notAfterP = validityP.getChild(1)
        if notAfterP.type == 0x17: # UTCTime
            self.notAfter = Time.parseASN1UTCTime(notAfterP.value)
        elif notAfterP.type == 0x18: # GeneralizedTime
            self.notAfter = Time.parseASN1GeneralizedTime(notAfterP.value)
        else:
            raise SyntaxError()

        # Get the hash values
        self.cert_sha256 = Digest.SHA256(data)
        self.key_sha256 = Digest.SHA256(spkiP.getTotalBytes())

        # Check if this is a TACK certificate:
        #Get the tbsCertificate
        versionP = tbsCertificateP.getChild(0)
        if versionP.type != 0xA0: # i.e. tag of [0], version
            return # X.509 version field not present
        versionPP = versionP.getTagged()
        if versionPP.value != bytearray([0x02]):
            return # X.509 version field does not equal v3

        # Find extensions element
        x = 0
        while 1:
            certFieldP = tbsCertificateP.getChild(x)
            if not certFieldP:
                raise SyntaxError("X.509 extensions not present")
            if certFieldP.type == 0xA3: # i.e. tag of [3], extensions
                break
            x += 1

        self.preExtBytes = data[versionP.offset : certFieldP.offset]
        self.extBytes = bytearray()

        # Iterate through extensions
        x = 0
        certFieldPP = certFieldP.getTagged()
        while 1:
            extFieldP = certFieldPP.getChild(x)
            if not extFieldP:
                break

            # Check the extnID and parse out TACK if present
            extnIDP = extFieldP.getChild(0)
            if extnIDP.value == TlsCertificate.OID_TACK:
                if self.tackExt:
                    raise SyntaxError("More than one TACK Extension")

                    # OK! We found a TACK, parse it..
                self.tackExt = TackExtension(extFieldP.getChild(1).value)
            else:
            # Collect all non-TACK extensions:
                self.extBytes += data[extFieldP.offset :\
                extFieldP.offset + extFieldP.getTotalLength()]
            x += 1

            # Finish copying the tail of the certificate
        self.postExtBytes = data[certFieldP.offset + certFieldP.getTotalLength():]

    @classmethod
    def create(cls, tackExt = None):
        tlsCert = cls()
        tlsCert.tackExt = tackExt
        tlsCert.preExtBytes = a2b_hex(
            "a003020102020100300d06092a864886f70d0101050500300f310d300b06035504031"
            "3045441434b301e170d3031303730353138303534385a170d34343037303431383035"
            "34385a300f310d300b060355040313045441434b301f300d06092a864886f70d01010"
            "10500030e00300b0204010203050203010001")
        # Below is BasicConstraints, saving space by omitting
        #self.extBytes = binascii.a2b_hex(\
        #"300c0603551d13040530030101ff")
        tlsCert.extBytes = bytearray()
        tlsCert.postExtBytes = a2b_hex(
            "300d06092a864886f70d01010505000303003993")

        # Parse the cert to populate its key_sha256, cert_sha256, and notAfter
        return cls(tlsCert.serialize())

    @classmethod
    def createFromBytes(cls, fileBytes):
        # May raise SyntaxError
        try:
            fileStr = bytesToStr(fileBytes, "ascii") # UnicodeDecodeError
            return cls.createFromPem(fileStr) # SyntaxError
        except (UnicodeDecodeError, SyntaxError) as e:
            # File had non-ASCII chars in it, *OR*
            # File did not PEM-decode
            return cls(bytearray(fileBytes))  # SyntaxError

    @classmethod
    def createFromPem(cls, s):
        return cls(PEMDecoder(s).decode("CERTIFICATE"))

    def serialize(self):
        b = bytearray(0)
        if self.tackExt:
            # type=SEQ,len=?,type=6,len=9(for OID),
            # type=4,len=?,TACK
            TACKBytes = self.tackExt.serialize()
            b = bytearray([4]) + asn1Length(len(TACKBytes)) + TACKBytes
            b = bytearray([6,9]) + TlsCertificate.OID_TACK + b
            b = bytearray([0x30]) + asn1Length(len(b)) + b

        b = b + self.extBytes # add non-TACK extensions after TACK
        # Add length fields for extensions and its enclosing tag
        b = bytearray([0x30]) + asn1Length(len(b)) + b
        b = bytearray([0xA3]) + asn1Length(len(b)) + b
        # Add prefix of tbsCertificate, then its type/length fields
        b = self.preExtBytes + b
        b = bytearray([0x30]) + asn1Length(len(b)) + b
        # Add postfix of Certificate (ie SignatureAlgorithm, SignatureValue)
        # then its prefix'd type/length fields
        b = b + self.postExtBytes
        b = bytearray([0x30]) + asn1Length(len(b)) + b
        return b

    def serializeAsPem(self):
        return PEMEncoder(self.serialize()).encode("CERTIFICATE")

    def __str__(self):
        s =\
        """key_sha256     = %s
notAfter       = %s
""" % (\
            Util.writeBytes(self.key_sha256),
            Time.posixTimeToStr(self.notAfter, True))
        if self.tackExt:
            s += "\n" + str(self.tackExt)
        return s

    def matches(self, tack):
        return self.key_sha256 == tack.target_hash

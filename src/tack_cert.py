from cryptomath import *
from compat import *
from asn1_parser import *
from pem import *
from tack_structures import *

################ TACK CERT ###

class TACK_Cert:
    # TBD!!!: lengths are hardcoded in write(), be aware if changing...
    oid_TACK = bytearray(b"\x2B\x06\x01\x04\x01\x82\xB0\x34\x01")
    oid_TACK_Break_Sigs = bytearray(b"\x2B\x06\x01\x04\x01\x82\xB0\x34\x02")
    
    def __init__(self):
        self.TACK = None
        self.break_sigs = None
        self.preExtBytes = None 
        self.extBytes = None
        self.postExtBytes = None
    
    def generate(self, pin=None, sig=None, break_sigs=None):
        self.TACK = None
        self.break_sigs = None
        self.preExtBytes = a2b_hex(
"a003020102020100300d06092a864886f70d0101050500300f310d300b06035504031"
"3045441434b301e170d3031303730353138303534385a170d33343037303431383035"
"34385a300f310d300b060355040313045441434b301f300d06092a864886f70d01010"
"10500030e00300b0204010203040203010001")
        # Below is BasicConstraints, saving space by omitting
        #self.extBytes = binascii.a2b_hex(\
#"300c0603551d13040530030101ff")
        self.extBytes = bytearray()
        self.postExtBytes = a2b_hex(
"300d06092a864886f70d01010505000303003993")
    
    def parse(self, b):
        try:
            b = dePem(b, "CERTIFICATE")
        except SyntaxError:
            pass        
        p = ASN1Parser(b)
        self.extBytes = bytearray()

        #Get the tbsCertificate
        tbsCertificateP = p.getChild(0)
        versionP = tbsCertificateP.getChild(0)        
        if versionP.type != 0xA0: # i.e. tag of [0], version
            raise SyntaxError("X.509 version field not present")
        versionPP = versionP.getTagged()
        if versionPP.value != bytearray([0x02]):
            raise SyntaxError("X.509 version field does not equal v3")

        # Find extensions element
        x = 0
        while 1:
            certFieldP = tbsCertificateP.getChild(x)
            if not certFieldP:
                raise SyntaxError("X.509 extensions not present")
            if certFieldP.type == 0xA3: # i.e. tag of [3], extensions
                break
            x += 1

        self.preExtBytes = b[versionP.offset : certFieldP.offset]
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
            if extnIDP.value == TACK_Cert.oid_TACK:
                if self.TACK:
                    raise SyntaxError("More than one TACK")                
                self.TACK = TACK()
                self.TACK.parse(extFieldP.getChild(1).value)                    
            elif extnIDP.value == TACK_Cert.oid_TACK_Break_Sigs:
                if self.break_sigs:
                    raise SyntaxError("More than one TACK_Break_Sigs")                
                self.break_sigs = TACK_Break_Sigs()
                self.break_sigs.parse(extFieldP.getChild(1).value)                    
            else:  
                # Collect all non-TACK extensions:
                self.extBytes += b[extFieldP.offset : \
                                extFieldP.offset + extFieldP.getTotalLength()]
            x += 1                

        # Finish copying the tail of the certificate
        self.postExtBytes = b[certFieldP.offset + certFieldP.getTotalLength():]
        
    def write(self, binary=False):                
        b = bytearray(0)
        if self.TACK:
            # type=SEQ,len=?,type=6,len=9(for OID),
            # type=4,len=?,TACK
            TACKBytes = self.TACK.write()            
            b = bytearray([4]) + asn1Length(len(TACKBytes)) + TACKBytes
            b = bytearray([6,9]) + self.oid_TACK + b
            b = bytearray([0x30]) + asn1Length(len(b)) + b
        if self.break_sigs:
            breakBytes = self.break_sigs.write()
            b2 = bytearray([4]) + asn1Length(len(breakBytes)) + breakBytes
            b2 = bytearray([6,9]) + self.oid_TACK_Break_Sigs + b2
            b2 = bytearray([0x30]) + asn1Length(len(b2)) + b2
            b += b2
        
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
        if not binary:
            b = pem(b, "CERTIFICATE")        
        return b

    def writeText(self):
        s = ""
        if self.TACK:
            s += self.TACK.writeText()
        if self.break_sigs:
            s += "\n"+self.break_sigs.writeText()
        if not s:
            return "No TACK structures\n"
        else:
            return s


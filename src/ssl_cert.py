from pem import *
from asn1 import *
from time_funcs import *
from cryptomath import *

################ SSL CERT ###

        
class SSL_Cert:
    def __init__(self):
        self.key_sha256 = bytearray(32)
        self.cert_sha256 = bytearray(32)
    
    def parse(self, b):
        try:
            b = dePem(b, "CERTIFICATE")
        except SyntaxError:
            pass
        p = ASN1Parser(b)

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
            self.notAfter = parseASN1UTCTime(notAfterP.value)
        elif notAfterP.type == 0x18: # GeneralizedTime
            self.notAfter = parseASN1GeneralizedTime(notAfterP.value)
        else:
            raise SyntaxError()            
        self.cert_sha256 = SHA256(b)
        self.key_sha256 = SHA256(spkiP.getTotalBytes())
    
    def writeText(self):
        s = \
"""key_sha256             = 0x%s
cert_sha256            = 0x%s
notAfter               = %s
\n""" % (\
        writeBytes(self.key_sha256),
        writeBytes(self.cert_sha256),
        posixTimeToStr(self.notAfter))
        return s
        

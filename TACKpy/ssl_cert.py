from .misc import *
from .pem import *
from .asn1 import *
from .time_funcs import *
from .cryptomath import *
from .tack_structures import *
from .constants import *

################ SSL CERT ###

# NOTE!: lengths are hardcoded in write(), be aware if changing...
oid_TACK = bytearray(b"\x2B\x06\x01\x04\x01\x82\xB0\x34\x01")
oid_TACK_Break_Sigs = bytearray(b"\x2B\x06\x01\x04\x01\x82\xB0\x34\x02")
        
class SSL_Cert:
    def __init__(self):
        self.key_sha256 = bytearray(32)
        self.cert_sha256 = bytearray(32)
        self.notAfter = 0
        # Below values are populated for TACK certs
        self.tack = None
        self.breakSigs = None
        # Below values hold cert contents excluding TACK stuff
        self.preExtBytes = None 
        self.extBytes = None
        self.postExtBytes = None        
        
    def create(self, tack=None, breakSigs=None):
        self.tack = tack
        self.breakSigs = breakSigs
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
        
    def open(self, filename):
        # May raise IOError or SyntaxError
        try:
            sslStr = open(filename, "rU").read() # IOError, UnicodeDecodeError
            self.parsePem(sslStr) # SyntaxError
            return
        except (UnicodeDecodeError, SyntaxError):
            # File had non-text chars in it (python3), *OR*
            # File did not PEM-decode
            pass
        sslBytes = bytearray(open(filename, "rb").read()) # IOError            
        self.parse(sslBytes)  # SyntaxError

    def matches(self, tack):
        if tack.sig.type == TACK_Sig_Type.v1_cert:
            return self.cert_sha256 == tack.sig.target_sha256
        elif tack.sig.type == TACK_Sig_Type.v1_key:
            return self.key_sha256 == tack.sig.target_sha256
        return False 
    
    def parsePem(self, s):
        b = dePem(s, "CERTIFICATE")
        self.parse(b)
    
    def parse(self, b):
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
            
        # Get the hash values            
        self.cert_sha256 = SHA256(b)
        self.key_sha256 = SHA256(spkiP.getTotalBytes())
        
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
            if extnIDP.value == oid_TACK:
                if self.tack:
                    raise SyntaxError("More than one TACK") 

                # OK! We found a TACK, parse it..               
                self.tack = TACK()
                self.tack.parse(extFieldP.getChild(1).value)       

            elif extnIDP.value == oid_TACK_Break_Sigs:
                if self.breakSigs:
                    raise SyntaxError("More than one TACK_Break_Sigs") 

                # OK! We found Break Sigs, parse them..
                b = extFieldP.getChild(1).value
                self.breakSigs = TACK_Break_Sig.parseBinaryList(b)
            else:  
                # Collect all non-TACK extensions:
                self.extBytes += b[extFieldP.offset : \
                                extFieldP.offset + extFieldP.getTotalLength()]
            x += 1                

        # Finish copying the tail of the certificate
        self.postExtBytes = b[certFieldP.offset + certFieldP.getTotalLength():]

    def write(self):                
        b = bytearray(0)
        if self.tack:
            # type=SEQ,len=?,type=6,len=9(for OID),
            # type=4,len=?,TACK
            TACKBytes = self.tack.write()            
            b = bytearray([4]) + asn1Length(len(TACKBytes)) + TACKBytes
            b = bytearray([6,9]) + oid_TACK + b
            b = bytearray([0x30]) + asn1Length(len(b)) + b
        if self.breakSigs:
            breakBytes = TACK_Break_Sig.writeBinaryList(self.breakSigs)
            b2 = bytearray([4]) + asn1Length(len(breakBytes)) + breakBytes
            b2 = bytearray([6,9]) + oid_TACK_Break_Sigs + b2
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
        return b

    def writePem(self):
        b = self.write()
        return pem(b, "CERTIFICATE")    
    def writeText(self):
        s = \
"""key_sha256     = 0x%s
cert_sha256    = 0x%s
notAfter       = %s
""" % (\
        writeBytes(self.key_sha256),
        writeBytes(self.cert_sha256),
        posixTimeToStr(self.notAfter, True))
        if self.tack or self.breakSigs:
            s += "\n"+writeTextTACKStructures(self.tack, self.breakSigs)
        return s

def testSSLCert():
    print("Testing SSL CERT")
    s = """
-----BEGIN CERTIFICATE-----
MIIFSzCCBDOgAwIBAgIHJ6JvWHUrOTANBgkqhkiG9w0BAQUFADCByjELMAkGA1UE
BhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAY
BgNVBAoTEUdvRGFkZHkuY29tLCBJbmMuMTMwMQYDVQQLEypodHRwOi8vY2VydGlm
aWNhdGVzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkxMDAuBgNVBAMTJ0dvIERhZGR5
IFNlY3VyZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTERMA8GA1UEBRMIMDc5Njky
ODcwHhcNMTEwNzA4MDAxOTU3WhcNMTIwNzA4MDAxOTU3WjBPMRQwEgYDVQQKFAsq
LnRyZXZwLm5ldDEhMB8GA1UECxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMRQw
EgYDVQQDFAsqLnRyZXZwLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAMgawQKi4zY4TTz1RNL7klt/ibvjG+jGqBYlc6qjUiTQORD3fUrdAF83Alav
JiC3rrwfvarL8KpPn7zQQOOk+APwzFxn0sVphDvAN8E7xI/cC7es08EYA9/DDN7r
VTe/wvbs77CL5AniRSJyAP5puvSUHgixingTgYmnkIgC+3ZFqyfz2uenxvkPkoUT
QEBkm2uEcBOwBMXAih1fdsuhEiJ9qpmejpIEvxLIDoMnCWTPs897zhwr3epQkn5g
lKQ9H+FnEo5Jf8YBM4YhAzwG/8pyfc8NtOHafKUb5PhSIC7Vy7N2EBQ4y9kDOZc+
r0Vguq4p+Nncc32JI/i1Cdj/lO0CAwEAAaOCAa4wggGqMA8GA1UdEwEB/wQFMAMB
AQAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMA4GA1UdDwEB/wQEAwIF
oDAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3JsLmdvZGFkZHkuY29tL2dkczEt
NTIuY3JsME0GA1UdIARGMEQwQgYLYIZIAYb9bQEHFwEwMzAxBggrBgEFBQcCARYl
aHR0cHM6Ly9jZXJ0cy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5LzCBgAYIKwYBBQUH
AQEEdDByMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5nb2RhZGR5LmNvbS8wSgYI
KwYBBQUHMAKGPmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3Np
dG9yeS9nZF9pbnRlcm1lZGlhdGUuY3J0MB8GA1UdIwQYMBaAFP2sYTKTbEXW4u6F
X5q653aZaMznMCEGA1UdEQQaMBiCCyoudHJldnAubmV0ggl0cmV2cC5uZXQwHQYD
VR0OBBYEFCYv4a9+enZGS27wqAv+TPfJOOb7MA0GCSqGSIb3DQEBBQUAA4IBAQA+
2OKO77vpwKtoKddDtamBokiVhHrfw0c7ALGysOXtss1CKV2WgH4FdNuh9pFkVZB2
mKZ7keS7EMW11OzgBR3pRRk0AkNYtDsOJEXA2+1NLFgrtdujHrDX4WIoi9MGbqB5
TfK08XufM7OP3yXDLtMxyUtyjprFhdxPE+9p/GJ0IVdZrMmzYTjyCOO8+okY9zAQ
RVUKuxd+eEaH3BpPAau4MP2n24gy6WEsJ2auB81ee9fDnx/tfKPqvyuc4r4/Z4aL
5CvQvlPHaG/TTXXNh3pZFl3d/J5/76ZfeQzQtZ+dCrE4a4601Q4hBBXEq5gQfaof
H4yTGzfDv+JLIICAIcCs
-----END CERTIFICATE-----"""    
    sslc = SSL_Cert()
    sslc.parsePem(s)
    assert(sslc.key_sha256 == a2b_hex("ffd30bcb84dbbc211a510875694354c58863d84fb7fc5853dfe36f4be2eb2e50"))
    assert(sslc.cert_sha256 == a2b_hex("1a50e3de3a153f33b314b67c1aacc2f59fc99c49b8449c33dcc3665663e2bff1"))
    assert(posixTimeToStr(sslc.notAfter, True) == "2012-07-08T00:19:57Z")
    assert(isinstance(sslc.writeText(), str))
    return 1        

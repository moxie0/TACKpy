# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

import unittest
from tack.tls.TlsCertificate import TlsCertificate
from tack.compat import a2b_hex
from tack.util.Time import Time

class CertificateTest(unittest.TestCase):

    def test_Certificate(self):
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
        sslc = TlsCertificate.createFromPem(s)
        assert(sslc.key_sha256 == a2b_hex("ffd30bcb84dbbc211a510875694354c58863d84fb7fc5853dfe36f4be2eb2e50"))
        assert(sslc.cert_sha256 == a2b_hex("1a50e3de3a153f33b314b67c1aacc2f59fc99c49b8449c33dcc3665663e2bff1"))
        assert(Time.posixTimeToStr(sslc.notAfter, True) == "2012-07-08T00:19:57Z")
        
        # Write to binary and re-parse it, then check again
        b = sslc.serialize()
        sslc2 = TlsCertificate(b)
        assert(sslc2.key_sha256 == a2b_hex("ffd30bcb84dbbc211a510875694354c58863d84fb7fc5853dfe36f4be2eb2e50"))
        assert(sslc2.cert_sha256 == a2b_hex("1a50e3de3a153f33b314b67c1aacc2f59fc99c49b8449c33dcc3665663e2bff1"))
        assert(Time.posixTimeToStr(sslc2.notAfter, True) == "2012-07-08T00:19:57Z")
        
        return 1

if __name__ == '__main__':
    unittest.main()
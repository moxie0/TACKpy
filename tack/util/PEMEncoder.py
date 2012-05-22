# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

from tack.compat import b2a_base64

class PEMEncoder:

    def __init__(self, data):
        self.data = data

    def encode(self, name):
        """Encode a payload bytearray into a PEM string.

        The input will be base64 encoded, then wrapped in a PEM prefix/postfix
        based on the name string, e.g. for name="CERTIFICATE":

        -----BEGIN CERTIFICATE-----
        MIIBXDCCAUSgAwIBAgIBADANBgkqhkiG9w0BAQUFADAPMQ0wCwYDVQQDEwRUQUNL
    ...
        KoZIhvcNAQEFBQADAwA5kw==
        -----END CERTIFICATE-----
        """
        s1 = b2a_base64(self.data)[:-1] # remove terminating \n
        s2 = ""
        while s1:
            s2 += s1[:64] + "\n"
            s1 = s1[64:]

        s = ("-----BEGIN %s-----\n" % name) + s2 +\
            ("-----END %s-----\n" % name)

        return s

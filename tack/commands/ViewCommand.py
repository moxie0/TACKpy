# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

import sys
from tack.commands.Command import Command
from tack.structures.Tack import Tack
from tack.structures.TackKeyFile import TackKeyFile
from tack.structures.TackBreakSig import TackBreakSig
from tack.tls.TlsCertificate import TlsCertificate
from tack.util.PEMDecoder import PEMDecoder

class ViewCommand(Command):

    def __init__(self, argv):
        Command.__init__(self, argv, "", "x", allowArgRemainder=True)

        if len(self.argRemainder) < 1:
            self.printError("Missing argument: file to view")
        if len(self.argRemainder) > 1:
            self.printError("Can only view one file")

    def execute(self):
        text, binary = self._readFileTextAndBinary(self.argRemainder[0])
        fileType     = None

        try:
            if text:
                decoder = PEMDecoder(text)
                if decoder.containsEncoded("TACK PRIVATE KEY"):
                    fileType = "Private Key"
                    kf       = TackKeyFile.createFromPem(text, None)
                    sys.stdout.write(str(kf))
                    return
                elif decoder.containsEncoded("TACK"):
                    fileType = "TACK"
                    tack     = Tack.createFromPem(text)
                    sys.stdout.write(str(tack))
                    return
                elif decoder.containsEncoded("TACK BREAK SIG"):
                    fileType = "Break Sig"
                    tbsList  = TackBreakSig.createFromPemList(text)
                    s        = ""
                    for tbs in tbsList:
                        s += str(tbs)
                    sys.stdout.write(s)
                    return
                elif decoder.containsEncoded( "CERTIFICATE"):
                    fileType = "Certificate"
                    sslc = TlsCertificate.createFromPem(text)
                    sys.stdout.write(str(sslc))
                    return
                    # Is it a certificate?
            try:
                sslc = TlsCertificate(binary)
                sys.stdout.write(str(sslc))
            except SyntaxError:
                self.printError("Unrecognized file type")
        except SyntaxError as e:
            self.printError("Error parsing %s: %s" % (fileType, e))

    @staticmethod
    def printHelp():
        print(
"""Views a TACK, TACK Key, TACK Break Sig, or certificate.

view [-x] <file> ("-" for stdin)

Optional arguments:
  -x                 : Use python crypto (not OpenSSL) to verify signatures
""")

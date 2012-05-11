from tack.commands.Command import Command
from tack.structures.Tack import Tack
from tack.structures.TackKeyFile import TackKeyFile
from tack.structures.TackBreakSig import TackBreakSig
from tack.tls.TlsCertificate import TlsCertificate
from tack.util.PEMDecoder import PEMDecoder

class ViewCommand(Command):

    def __init__(self, argv):
        Command.__init__(self, argv, "", "")

        if len(argv) < 1:
            self.printError("Missing argument: file to view")
        if len(argv) > 1:
            self.printError("Can only view one file")


    def _readFile(self, argv):
        try:
            # Read both binary (bytearray) and text (str) versions of the input
            b = bytearray(open(argv[0], "rb").read())
            try:
                s = open(argv[0], "rU").read()
            except UnicodeDecodeError:
                # Python3 error, so it must be a binary file; not text
                s = None

            return s, b
        except IOError:
            self.printError("Error opening file: %s" % argv[0])

    def execute(self):
        text, binary = self._readFile(self.argv)
        fileType     = None

        try:
            if text:
                decoder = PEMDecoder(text)
                if decoder.containsEncoded("TACK PRIVATE KEY"):
                    fileType = "Private Key"
                    kf       = TackKeyFile.createFromPem(text, None)
                    print(str(kf))
                    return
                elif decoder.containsEncoded("TACK"):
                    fileType = "TACK"
                    tack     = Tack.createFromPem(text)
                    print(str(tack))
                    return
                elif decoder.containsEncoded("TACK BREAK SIG"):
                    fileType = "Break Sig"
                    tbsList  = TackBreakSig.createFromPemList(text)
                    s        = ""
                    for tbs in tbsList:
                        s += str(tbs)
                    print(s)
                    return
                elif decoder.containsEncoded( "CERTIFICATE"):
                    fileType = "Certificate"
                    sslc = TlsCertificate()
                    sslc.parsePem(text)
                    print(sslc.writeText())
                    return
                    # Is it a certificate?
            try:
                sslc = TlsCertificate()
                sslc.parse(binary)
                print(sslc.writeText())
            except SyntaxError:
                self.printError("Unrecognized file type")
        except SyntaxError as e:
            self.printError("Error parsing %s: %s" % (fileType, e))

    @staticmethod
    def printHelp():
        print(\
"""Views a TACK, TACK Key, TACK Break Sig, or certificate.

view <file>
""")

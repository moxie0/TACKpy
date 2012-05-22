# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

import sys
from tack.commands.Command import Command
from tack.structures.Tack import Tack
from tack.structures.TackActivation import TackActivation
from tack.structures.TackExtension import TackExtension
from tack.tls.TlsCertificate import TlsCertificate
from tack.util.PEMDecoder import PEMDecoder

class CertificateCommand(Command):

    def __init__(self, argv):
        Command.__init__(self, argv, "oib", "v")

        self.outputFile, self.outputFileName = self.getOutputFile()
        (self.inputTack, self.inputCertificate) = self._getInputFile()
        self.breakSignatures                 = self._getBreakSignatures()

    def execute(self):
        if self.inputTack is not None:
            tackExtension = TackExtension.create(self.inputTack, self.breakSignatures,
                                                    TackActivation.DISABLED)

            tlsCertificate = TlsCertificate.create(tackExtension)
            self.outputFile.write(tlsCertificate.serializeAsPem())

            if self.isVerbose():
                sys.stderr.write(str(tackExtension))

        elif self.inputCertificate is not None:
            if self.breakSignatures is not None:
                self.printError("Invalid arguments: break sigs with TACK cert.")

            s = ""
            if self.inputCertificate.tackExt:
                if self.inputCertificate.tackExt.tack:
                    s += self.inputCertificate.tackExt.tack.serializeAsPem()
                if self.inputCertificate.tackExt.break_sigs:
                    for bs in self.inputCertificate.tackExt.break_sigs:
                        s += bs.serializeAsPem()

            self.outputFile.write(s)

            if self.isVerbose():
                sys.stderr.write(str(self.inputCertificate))
        else:
            assert(False)

    def _getBreakSignatures(self):
        fileName = self._getOptionValue("-b")

        if fileName is None:
            return None

        try:
            contents = open(fileName, "r").read()
        except IOError:
            self.printError("Error opening break signature: %s" % fileName)

    def _getInputFile(self):
        fileName = self._getOptionValue("-i")
        if fileName is None:
            self.printError("-i missing (Certificate or TACK)")
        try:

            text, binary = self._readFileTextAndBinary(fileName)
            if text:
                pem = PEMDecoder(text)
                if pem.containsEncoded("TACK"):
                    return (Tack.createFromPem(text), None)
                elif pem.containsEncoded("CERTIFICATE"):
                    return (None, TlsCertificate.createFromPem(text))
                else:
                    self.printError("Unrecognized input file: %s" % fileName)
            else:
                return (None, TlsCertificate(binary))

        except IOError:
            self.printError("Error opening input file: %s" % fileName)
        except SyntaxError:
            self.printError("Error parsing input file: %s" % fileName)

    @staticmethod
    def printHelp():
        print(
"""Creates a TACK certificate with the input TACK and optional Break Sigs.

(Alternatively, if input is a TACK certificate, writes out the TACK and/or
Break Signatures as PEM files).

cert -i (TACK or CERT)

Optional arguments:
  -v                 : Verbose
  -b BREAKSIGS       : Include Break Signatures from this file.
  -o FILE            : Write the output to this file (instead of stdout)
""")

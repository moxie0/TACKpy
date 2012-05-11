import sys
from tack.commands.Command import Command
from tack.structures.Tack import Tack
from tack.structures.TackActivation import TackActivation
from tack.structures.TackBreakSig import TackBreakSig
from tack.structures.TackExtension import TackExtension
from tack.tls.TlsCertificate import TlsCertificate
from tack.util.PEMDecoder import PEMDecoder

class CertificateCommand(Command):

    def __init__(self, argv):
        Command.__init__(self, argv, "oib", "v")

        self.outputFile, self.outputFileName = self.getOutputFile()
        self.inputTack                       = self._getInputTack()
        self.inputCertificate                = self._getInputCertificate()
        self.breakSignatures                 = self._getBreakSignatures()

        if self.inputTack is None and self.inputCertificate is None:
            self.printError("-i missing")

    def execute(self):
        if self.inputTack is not None:
            tackExtension = TackExtension.create(self.inputTack, self.breakSignatures,
                                                    TackActivation.DISABLED)
            tlsCertificate = TlsCertificate()
            tlsCertificate.create(tackExtension)

            self.outputFile.write(tlsCertificate.writePem())

            if self.isVerbose():
                sys.stderr.write(str(tackExtension) + "\n")

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
                sys.stderr.write(self.inputCertificate.writeText() + "\n")

    def _getBreakSignatures(self):
        fileName = self._getOptionValue("-b")

        if fileName is None:
            return None

        contents = open(fileName, "r").read()

        return TackBreakSig.createFromPemList(contents)

    def _getInputTack(self):
        contents = self._getInputFileContents()

        if contents is None:
            return None

        if PEMDecoder(contents).containsEncoded("TACK"):
            return Tack.createFromPem(contents)

        return None

    def _getInputCertificate(self):
        contents = self._getInputFileContents()

        if contents is None:
            return None

        if PEMDecoder(contents).containsEncoded("CERTIFICATE"):
            certificate = TlsCertificate()
            certificate.open(self._getOptionValue("-i"))
            return certificate

    def _getInputFileContents(self):
        fileName = self._getOptionValue("-i")

        if fileName is None:
            return None

        return open(fileName, "r").read()

    @staticmethod
    def printHelp():
        print(
"""Creates a TACK certificate with the input TACK and optional Break Sigs.

(Alternatively, if input is a TACK certificate, writes out the TACK and/or
Break Signatures as PEM files).

tackcert -i (TACK or CERT)

Optional arguments:
  -v                 : Verbose
  -b BREAKSIGS       : Include Break Signatures from this file.
  -o FILE            : Write the output to this file (instead of stdout)
""")

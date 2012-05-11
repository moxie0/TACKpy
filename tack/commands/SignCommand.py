import sys
import time
import math
from tack.commands.Command import Command
from tack.structures.Tack import Tack
from tack.tls.TlsCertificate import TlsCertificate
from tack.util.Time import Time

class SignCommand(Command):

    def __init__(self, argv):
        Command.__init__(self, argv, "kcopmgen", "v")

        self.password                        = self.getPassword()
        self.keyfile                         = self.getKeyFile(self.password)

        self.certificate                     = self._getCertificate()
        self.generation                      = self._getGeneration()
        self.min_generation                  = self._getMinGeneration()
        self.expiration                      = self._getExpiration()
        self.numArg                          = self._getNumArg()
        # If -n, then -o is a filename prefix only, so is not opened
        if self.numArg:
            self.outputFileName              = self.getOutputFileName()
            return
        self.outputFile, self.outputFileName = self.getOutputFile()


    def execute(self):
        if not self.numArg:
  
            tack = Tack.create(self.keyfile.getPublicKey(), self.keyfile.getPrivateKey(), self.min_generation,
                            self.generation, self.expiration, self.certificate.key_sha256)

            self.outputFile.write(self.addPemComments(tack.serializeAsPem()))

            if self.isVerbose():
                sys.stderr.write(str(tack) + "\n")
        else:
            (numTacks, interval) = self.numArg

            if not self.outputFileName:
                self.printError("-o required with -n")

            for x in range(numTacks):
                tack = Tack.create(self.keyfile.getPublicKey(), self.keyfile.getPrivateKey(), self.min_generation,
                            self.generation, self.expiration, self.certificate.key_sha256)

                outputFile = open(self.outputFileName + "_%04d.pem" % x, "w")
                outputFile.write(self.addPemComments(tack.serializeAsPem()))
                outputFile.close()

                if self.isVerbose():
                    sys.stderr.write(str(tack) + "\n")

                self.expiration += interval

    def _getCertificate(self):
        certificateFile = self._getOptionValue("-c")

        if not certificateFile:
            self.printError("-c missing (Certificate)")

        try:
            inCert = TlsCertificate()
            inCert.open(certificateFile)
            return inCert
        except SyntaxError:
            self.printError("Certificate malformed: %s" % certificateFile)
        except IOError:
            self.printError("Error opening certificate: %s" % certificateFile)

    def _getExpiration(self):
        expiration = self._getOptionValue("-e")

        if expiration is None and self._getNumArg() is None:
            return int(math.ceil(self._getCertificate().notAfter / 60.0))
        else:
            try:
                return Time.parseTimeArg(expiration)
            except SyntaxError as e:
                self.printError(e)

    def _getNumArg(self):
        numArgRaw = self._getOptionValue("-n")

        if numArgRaw is None:
            return None

        try:
            leftArg, rightArg = numArgRaw.split("@") # could raise ValueError
            numTacks = int(leftArg) # could raise ValueError
            interval = Time.parseDurationArg(rightArg) # SyntaxError
            if numTacks < 1 or numTacks >= 10000:
                raise ValueError()
            return numTacks, interval
        except (ValueError, SyntaxError):
            self.printError("Bad -n NUMTACKS: %s:" % numArgRaw)

    def _getGeneration(self):
        generation = self._getOptionValue("-g")

        if generation is None:
            generation = self._getMinGeneration()

        try:
            generation = int(generation) # Could raise ValueError
            if generation < 0 or generation>255:
                raise ValueError()
        except ValueError:
            self.printError("Bad generation: %s" % generation)

        if generation < self._getMinGeneration():
            self.printError("generation must be >= min_generation")

        return generation

    def _getMinGeneration(self):
        min_generation = self._getOptionValue("-m")

        if min_generation is None:
            min_generation = 0

        try:
            min_generation = int(min_generation) # Could raise ValueError
            if min_generation < 0 or min_generation>255:
                raise ValueError()
        except ValueError:
            self.printError("Bad min_generation: %s" % min_generation)

        return min_generation

    @staticmethod
    def printHelp():
        s = Time.posixTimeToStr(time.time())
        print(
"""Creates a TACK based on a target certificate.

  sign -k KEY -c CERT

  -k KEY             : Use this TACK key file
  -c CERT            : Sign this certificate's public key

Optional arguments:
  -v                 : Verbose
  -o FILE            : Write the output to this file (instead of stdout)
  -p PASSWORD        : Use this TACK key password instead of prompting
  -m MIN_GENERATION  : Use this min_generation number (0-255)
  -g GENERATION      : Use this generation number (0-255)
  -e EXPIRATION      : Use this UTC time for expiration
                         ("%s", "%sZ",
                          "%sZ", "%sZ" etc.)
                       Or, specify a delta from current time:
                       ("5m", "30d", "1d12h5m", "0m", etc.) 
                       If not specified, the certificate's notAfter is used.
  - n NUM@INTERVAL   : Generate NUM TACKs, with expiration times spaced
                       out by INTERVAL (see -e for delta syntax).  The
                       -o argument is used as a filename prefix, and the
                       -e argument is used as the first expiration time.
""" % (s, s[:13], s[:10], s[:4]))


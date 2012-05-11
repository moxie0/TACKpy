import getopt
import getpass
import sys
import time
from tack.structures.TackKeyFile import TackKeyFile
from tack.util.Time import Time
from tack.version import __version__
from tack.InvalidPasswordException import InvalidPasswordException

class Command:

    def __init__(self, argv, options, flags):
        try:
            self.argv                   = argv
            self.flags                  = flags
            self.options                = ":".join(options) + ":"
            self.values, self.remainder = getopt.getopt(argv, self.options + self.flags)
        except getopt.GetoptError as e:
            self.printError(e)

    def isVerbose(self):
        return self._containsOption("-v")

    def getPassword(self):
        return self._getOptionValue("-p")

    def getKeyFile(self, password):
        keyPemFile = self._getOptionValue("-k")

        if not keyPemFile:
            self.printError("-k missing (TACK Key)")

        if not password:
            password = self._promptPassword()

        try:
            keyPemData = open(keyPemFile, "rU").read()

            while True:
                try:
                    inKey = TackKeyFile.createFromPem(keyPemData, password)
                    return inKey
                except InvalidPasswordException as ipe:
                    sys.stderr.write("Password incorrect!\n")
                    password = self._promptPassword()
                except SyntaxError:
                    self.printError("Error processing TACK Key File")

        except IOError:
            self.printError("Error opening TACK Key File: %s" % keyPemFile)


    def getOutputFile(self):
        output = None

        try:
            output = self._getOptionValue("-o")

            if output is None:
                return sys.stdout, None
            else:
                return open(output, "w"), output
        except IOError:
            self.printError("Error opening output file: %s" % output)

    def getOutputFileName(self):
        return self._getOptionValue("-o")

    def addPemComments(self, inStr):
        """Add pre-PEM metadata/comments to PEM strings."""
        versionStr = __version__
        timeStr = Time.posixTimeToStr(time.time(), True)
        outStr = "Created by tack.py %s\nCreated at %s\n%s" %\
                 (versionStr, timeStr, inStr)
        return outStr

    def _promptPassword(self):
        return getpass.getpass("Enter password for key file: ")

    def _getOptionValue(self, flag):
        for option, value in self.values:
            if option == flag:
                return value

        return None

    def _containsOption(self, flag):
        for option, value in self.values:
            if option == flag:
                return True

    def printError(self, error):
        """Print error message and exit"""
        sys.stderr.write("ERROR: %s\n" % error)
        sys.exit(-1)


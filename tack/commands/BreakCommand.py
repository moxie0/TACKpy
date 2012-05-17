# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

import sys
from tack.commands.Command import Command
from tack.structures.TackBreakSig import TackBreakSig

class BreakCommand(Command):

    def __init__(self, argv):
        Command.__init__(self, argv, "pok", "vx")
        self.password                        = self.getPassword()
        self.outputFile, self.outputFileName = self.getOutputFile()
        self.keyfile                         = self.getKeyFile(self.getPassword())

    def execute(self):
        breakSig = TackBreakSig.create(self.keyfile.getPublicKey(), self.keyfile.getPrivateKey())
        self.outputFile.write(self.addPemComments(breakSig.serializeAsPem()))

        if self.isVerbose():
            self.writeCryptoVersion()
            sys.stderr.write(str(breakSig))

    @staticmethod
    def printHelp():
        print(
"""Creates a break signature based on an input TACK key file.

  break -k KEY

  -k KEY             : Use this TACK key file ("-" for stdin)

Optional arguments:
  -v                 : Verbose
  -x                 : Use python crypto (not OpenSSL)  
  -o FILE            : Write the output to this file (instead of stdout)
  -p PASSWORD        : Use this TACK key password instead of prompting
""")

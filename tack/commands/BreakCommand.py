import sys
from tack.commands.Command import Command
from tack.structures.TackBreakSig import TackBreakSig

class BreakCommand(Command):

    def __init__(self, argv):
        Command.__init__(self, argv, "pok", "v")
        self.password                        = self.getPassword()
        self.outputFile, self.outputFileName = self.getOutputFile()
        self.key                             = self.getKey(self.getPassword())

    def execute(self):
        breakSig = TackBreakSig.create(self.key.getPublicKey(), self.key.getPrivateKey())
        self.outputFile.write(self.addPemComments(breakSig.serializeAsPem()))

        if self.isVerbose():
            sys.stderr.write(str(breakSig) + "\n")

    @staticmethod
    def printHelp():
        print(\
"""Creates a break signature based on an input TACK key file.

  break -k KEY

  -k KEY             : Use this TACK key file

Optional arguments:
  -v                 : Verbose
  -o FILE            : Write the output to this file (instead of stdout)
  -p PASSWORD        : Use this TACK key password instead of prompting
""")
